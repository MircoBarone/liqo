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

package connection

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/gateway/connection/conncheck"
	timeutils "github.com/liqotech/liqo/pkg/utils/time"
)

// UpdateConnectionStatus updates the status of a connection.
func UpdateConnectionStatus(ctx context.Context, cl client.Client, opts *Options, connection *networkingv1beta1.Connection,
	value networkingv1beta1.ConnectionStatusValue, latency time.Duration, timestamp time.Time) error {
	if connection.Status.Value != value ||
		timestamp.Sub(connection.Status.Latency.Timestamp.Time) > opts.PingUpdateStatusInterval {
		if connection.Status.Value != value {
			klog.Infof("changing connection %q status to %q",
				client.ObjectKeyFromObject(connection).String(), value)
		}
		connection.Status.Latency = networkingv1beta1.ConnectionLatency{
			Value:     timeutils.FormatLatency(latency),
			Timestamp: metav1.NewTime(timestamp),
		}
		connection.Status.Interfaces = nil
		connection.Status.Value = value
		if err := cl.Status().Update(ctx, connection); err != nil {
			return fmt.Errorf("unable to update connection %q: %w",
				client.ObjectKeyFromObject(connection).String(), err)
		}
	}
	return nil
}

// UpdateConnectionStatusMultitunnel updates the status of a connection with multitunnel data.
func UpdateConnectionStatusMultitunnel(ctx context.Context, cl client.Client, opts *Options, connection *networkingv1beta1.Connection,
	timestamp time.Time, snapshot map[string]map[int]conncheck.Peer) error {

	if len(snapshot) > 1 {
		return fmt.Errorf("unexpected multiple clusterIDs in snapshot for connection %q", connection.Name)
	}

	var totalLat time.Duration
	var maxLat time.Duration
	var count int
	allConn := true

	interfacesStatus := []networkingv1beta1.InterfaceStatus{}

	for _, interfaces := range snapshot {
		for id, p := range interfaces {

			if !p.Connected {
				allConn = false
			} else {
				count++
				totalLat += p.Latency
				if p.Latency > maxLat {
					maxLat = p.Latency
				}
			}

			ifaceValue := networkingv1beta1.Connected
			if !p.Connected {
				ifaceValue = networkingv1beta1.ConnectionError
			}

			interfacesStatus = append(interfacesStatus, networkingv1beta1.InterfaceStatus{
				ID:      id,
				Status:  ifaceValue,
				Latency: timeutils.FormatLatency(p.Latency),
			})
		}
	}

	avgLat := time.Duration(0)
	if count > 0 {
		avgLat = totalLat / time.Duration(count)
	}

	newValue := networkingv1beta1.Connected
	if !allConn {
		newValue = networkingv1beta1.ConnectionError
	}

	if connection.Status.Value != newValue {
		klog.Infof("Changing multitunnel connection %q status to %q (interfaces: %d/%d connected)",
			client.ObjectKeyFromObject(connection).String(), newValue, count, len(interfacesStatus))
	}

	connection.Status.Value = newValue
	connection.Status.Latency = networkingv1beta1.ConnectionLatency{
		Value:     timeutils.FormatLatency(avgLat),
		MaxValue:  timeutils.FormatLatency(maxLat),
		Timestamp: metav1.NewTime(timestamp),
	}

	connection.Status.Interfaces = interfacesStatus

	if err := cl.Status().Update(ctx, connection); err != nil {
		return fmt.Errorf("unable to update multitunnel connection status %q: %w",
			client.ObjectKeyFromObject(connection).String(), err)
	}

	return nil
}
