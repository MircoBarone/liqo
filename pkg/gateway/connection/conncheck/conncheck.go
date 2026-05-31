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
	// key is the target interfaceID (the name of the interface)
	senders        map[string]*Sender
	runningSenders map[string]*Sender
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
		senders:        make(map[string]*Sender),
		runningSenders: make(map[string]*Sender),
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

// AddSender adds a sender.
func (c *ConnChecker) AddSender(ctx context.Context, interfaceID, ip string, updateCallback UpdateFunc) error {
	var err error

	if interfaceID == "" {
		return fmt.Errorf("interfaceID cannot be empty")
	}

	c.sm.Lock()
	defer c.sm.Unlock()

	if _, ok := c.senders[interfaceID]; ok {
		return NewDuplicateError(interfaceID)
	}

	ctxSender, cancelSender := context.WithCancel(ctx)
	c.senders[interfaceID], err = NewSender(ctxSender, c.opts, interfaceID, cancelSender, c.conn, ip)
	if err != nil {
		return fmt.Errorf("failed to create sender %q: %w", interfaceID, err)
	}

	err = c.receiver.InitPeer(interfaceID, updateCallback)
	if err != nil {
		return fmt.Errorf("failed to init peer: %w", err)
	}

	klog.Infof("conncheck sender %q added", interfaceID)
	return nil
}

// RunSender runs a sender.
func (c *ConnChecker) RunSender(interfaceID string) {
	sender, err := c.setRunning(interfaceID)
	if err != nil {
		klog.Errorf("conncheck sender %s doesn't start for an error: %s", interfaceID, err)
		return
	}

	klog.Infof("conncheck sender %q starting against %q", interfaceID, sender.raddr.IP.String())

	if err := wait.PollUntilContextCancel(sender.Ctx, c.opts.PingInterval, false, func(_ context.Context) (done bool, err error) {
		err = c.senders[interfaceID].SendPing()
		if err != nil {
			klog.Warningf("failed to send ping: %s", err)
		}
		return false, nil
	}); err != nil {
		klog.Errorf("conncheck sender %s stopped for an error: %s", interfaceID, err)
	}

	klog.Infof("conncheck sender %s stopped", interfaceID)
}

// DelAndStopSender stops and deletes a sender. If sender has been already stoped and deleted is a no-op function.
func (c *ConnChecker) DelAndStopSender(interfaceID string) {
	c.sm.Lock()
	defer c.sm.Unlock()

	c.receiver.mMu.Lock()
	defer c.receiver.mMu.Unlock()

	if _, ok := c.senders[interfaceID]; ok {
		c.senders[interfaceID].cancel()
		delete(c.senders, interfaceID)
	}

	delete(c.runningSenders, interfaceID)
	delete(c.receiver.peers, interfaceID)
}

// GetLatency returns the latency with interfaceID.
func (c *ConnChecker) GetLatency(interfaceID string) (time.Duration, error) {
	c.receiver.mMu.RLock()
	peer, ok := c.receiver.peers[interfaceID]
	c.receiver.mMu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("sender %s not found", interfaceID)
	}

	peer.pMu.Lock()
	defer peer.pMu.Unlock()
	return peer.latency, nil
}

// GetConnected returns the connection status with interfaceID.
func (c *ConnChecker) GetConnected(interfaceID string) (bool, error) {
	c.receiver.mMu.RLock()
	peer, ok := c.receiver.peers[interfaceID]
	c.receiver.mMu.RUnlock()
	if !ok {
		return false, fmt.Errorf("sender %s not found", interfaceID)
	}

	peer.pMu.Lock()
	defer peer.pMu.Unlock()
	return peer.connected, nil
}

func (c *ConnChecker) setRunning(interfaceID string) (*Sender, error) {
	c.sm.Lock()
	defer c.sm.Unlock()
	sender, ok := c.senders[interfaceID]
	if !ok {
		return nil, fmt.Errorf("sender %s not found", interfaceID)
	}

	if _, ok := c.runningSenders[interfaceID]; ok {
		return nil, fmt.Errorf("sender %s already running", interfaceID)
	}
	c.runningSenders[interfaceID] = sender
	return sender, nil
}
