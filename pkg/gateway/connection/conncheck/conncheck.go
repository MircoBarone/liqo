// Copyright 2019-2026 The Liqo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conncheck

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

// ConnChecker is a struct that holds the receiver and senders.
type ConnChecker struct {
	opts     *Options
	receiver *Receiver
	// senders are indexed by clusterID and interfaceID (multi-tunnel support).
	senders        map[string]map[int]*Sender
	runningSenders map[string]map[int]*Sender
	sm             sync.RWMutex
	conn           *net.UDPConn
}

// NewConnChecker creates a new ConnChecker.
func NewConnChecker(opts *Options) (*ConnChecker, error) {
	addr := &net.UDPAddr{
		Port: opts.PingPort,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP socket %s : %w", addr, err)
	}
	klog.V(4).Infof("conncheck socket: listening on %s", addr)
	connChecker := ConnChecker{
		opts:           opts,
		receiver:       NewReceiver(conn, opts),
		senders:        make(map[string]map[int]*Sender),
		runningSenders: make(map[string]map[int]*Sender),
		conn:           conn,
	}
	return &connChecker, nil
}

// RunReceiver runs the receiver.
func (c *ConnChecker) RunReceiver(ctx context.Context) {
	c.receiver.Run(ctx)
}

// RunReceiverDisconnectObserver runs the receiver disconnect observer.
func (c *ConnChecker) RunReceiverDisconnectObserver(ctx context.Context) {
	c.receiver.RunDisconnectObserver(ctx)
}

// RunReceiverPeerMonitor runs the aggregator for multi-interface monitoring.
func (c *ConnChecker) RunReceiverPeerMonitor(ctx context.Context) {
	c.receiver.RunPeerMonitor(ctx)
}

// SetMultitunnelUpdateCallback sets the callback for multitunnel status updates.
func (c *ConnChecker) SetMultitunnelUpdateCallback(cb MultitunnelUpdateFunc) {
	c.receiver.SetMultitunnelUpdateCallback(cb)
}

// AddSender adds a sender.
func (c *ConnChecker) AddSender(ctx context.Context, clusterID, ip string, updateCallback UpdateFunc, interfaceID int, label string) error {
	var err error

	if clusterID == "" {
		return fmt.Errorf("clusterID cannot be empty")
	}

	c.sm.Lock()
	defer c.sm.Unlock()

	if c.senders[clusterID] == nil {
		c.senders[clusterID] = make(map[int]*Sender)
	}

	if _, ok := c.senders[clusterID][interfaceID]; ok {
		return NewDuplicateError(label)
	}

	ctxSender, cancelSender := context.WithCancel(ctx)
	c.senders[clusterID][interfaceID], err = NewSender(ctxSender, c.opts, clusterID, cancelSender, c.conn, ip, interfaceID)
	if err != nil {
		return fmt.Errorf("failed to create sender %s: %w", label, err)
	}

	err = c.receiver.InitPeer(clusterID, updateCallback, interfaceID)
	if err != nil {
		return fmt.Errorf("failed to init peer %s: %w", label, err)
	}
	klog.Infof("conncheck sender %q added", label)

	return nil
}

// RunSender runs a sender.
func (c *ConnChecker) RunSender(clusterID string, interfaceID int, label string) {
	sender, err := c.setRunning(clusterID, interfaceID, label)
	if err != nil {
		klog.Errorf("conncheck sender %s  doesn't start for an error: %s", label, err)
		return
	}

	klog.Infof("conncheck sender %q starting against %q", label, sender.raddr.IP.String())

	if err := wait.PollUntilContextCancel(sender.Ctx, c.opts.PingInterval, false, func(_ context.Context) (done bool, err error) {
		err = c.senders[clusterID][interfaceID].SendPing()
		if err != nil {
			klog.Warningf("failed to send ping: %s", err)
		}
		return false, nil
	}); err != nil {
		klog.Errorf("conncheck sender %s stopped for an error: %s", label, err)
	}

	klog.Infof("conncheck sender %s stopped", label)
}

// DelAndStopSender stops and deletes a sender. If sender has been already stoped and deleted is a no-op function.
func (c *ConnChecker) DelAndStopSender(clusterID string, interfaceID int) {
	c.sm.Lock()
	defer c.sm.Unlock()

	c.receiver.m.Lock()
	defer c.receiver.m.Unlock()

	if _, ok := c.senders[clusterID][interfaceID]; ok {
		c.senders[clusterID][interfaceID].cancel()
		delete(c.senders[clusterID], interfaceID)

		if len(c.senders[clusterID]) == 0 {
			delete(c.senders, clusterID)
		}
	}

	if c.runningSenders[clusterID] != nil {
		delete(c.runningSenders[clusterID], interfaceID)

		if len(c.runningSenders[clusterID]) == 0 {
			delete(c.runningSenders, clusterID)
		}
	}
	delete(c.receiver.peers, clusterID)
}

// GetLatency returns the latency with clusterID.
func (c *ConnChecker) GetLatency(clusterID string, interfaceID int) (time.Duration, error) {
	c.receiver.m.RLock()
	defer c.receiver.m.RUnlock()
	if peer, ok := c.receiver.peers[clusterID][interfaceID]; ok {
		return peer.Latency, nil
	}
	return 0, fmt.Errorf("sender %s (%d) not found", clusterID, interfaceID)
}

// GetConnected returns the connection status with clusterID.
func (c *ConnChecker) GetConnected(clusterID string, interfaceID int) (bool, error) {
	c.receiver.m.RLock()
	defer c.receiver.m.RUnlock()
	if peer, ok := c.receiver.peers[clusterID][interfaceID]; ok {
		return peer.Connected, nil
	}
	return false, fmt.Errorf("sender %s (%d) not found", clusterID, interfaceID)
}

func (c *ConnChecker) setRunning(clusterID string, interfaceID int, label string) (*Sender, error) {
	c.sm.Lock()
	defer c.sm.Unlock()
	if c.runningSenders[clusterID] == nil {
		c.runningSenders[clusterID] = make(map[int]*Sender)
	}
	sender, ok := c.senders[clusterID][interfaceID]
	if !ok {
		return nil, fmt.Errorf("sender %s not found", label)
	}

	if _, ok := c.runningSenders[clusterID][interfaceID]; ok {
		return nil, fmt.Errorf("sender %s already running", label)
	}
	c.runningSenders[clusterID][interfaceID] = sender
	return sender, nil
}
