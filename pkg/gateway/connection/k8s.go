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
	"github.com/liqotech/liqo/pkg/consts"
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
		ts := metav1.NewTime(timestamp)
		connection.Status.Latency = networkingv1beta1.ConnectionLatency{
			Value:     timeutils.FormatLatency(latency),
			Timestamp: &ts,
		}
		connection.Status.Value = value
		if err := cl.Status().Update(ctx, connection); err != nil {
			return fmt.Errorf("unable to update connection %q: %w",
				client.ObjectKeyFromObject(connection).String(), err)
		}
	}
	return nil
}

// UpdateTunnelStatus updates the status of a single tunnel using SSA.
func UpdateTunnelStatus(ctx context.Context, cl client.Client, opts *Options, connection *networkingv1beta1.Connection,
	value networkingv1beta1.ConnectionStatusValue, latency time.Duration, timestamp time.Time, interfaceID string) error {
	if !shouldUpdateTunnelStatus(connection, interfaceID, value, timestamp, opts) {
		return nil
	}
	var tsPtr *metav1.Time
	if !timestamp.IsZero() {
		t := metav1.NewTime(timestamp)
		tsPtr = &t
	}
	patch := &networkingv1beta1.Connection{
		TypeMeta: metav1.TypeMeta{
			APIVersion: networkingv1beta1.GroupVersion.String(),
			Kind:       networkingv1beta1.ConnectionKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      connection.Name,
			Namespace: connection.Namespace,
		},
		Status: networkingv1beta1.ConnectionStatus{
			Tunnels: []networkingv1beta1.TunnelStatus{
				{
					InterfaceID: interfaceID,
					Value:       value,
					Latency: networkingv1beta1.ConnectionLatency{
						Value:     timeutils.FormatLatency(latency),
						Timestamp: tsPtr,
					},
				},
			},
		},
	}
	//nolint:staticcheck // Keep SSA until ApplyConfiguration migration.
	return cl.Status().Patch(ctx, patch, client.Apply,
		client.FieldOwner(interfaceID),
	)
}

func shouldUpdateTunnelStatus(connection *networkingv1beta1.Connection, interfaceID string,
	value networkingv1beta1.ConnectionStatusValue, timestamp time.Time, opts *Options) bool {
	var lastTime time.Time
	var lastValue networkingv1beta1.ConnectionStatusValue
	found := false
	for _, tunnel := range connection.Status.Tunnels {
		if tunnel.InterfaceID == interfaceID {
			found = true
			lastValue = tunnel.Value

			if tunnel.Latency.Timestamp != nil {
				lastTime = tunnel.Latency.Timestamp.Time
			}

			break
		}
	}

	if !found {
		return true
	}
	return lastValue != value ||
		timestamp.Sub(lastTime) > opts.PingUpdateStatusInterval
}

// UpdateConnectionStatusAggregated updates the global connection status and average latency using SSA.
// This function ensures the aggregator only manages global fields, preserving individual tunnel data.
func UpdateConnectionStatusAggregated(ctx context.Context, cl client.Client,
	connection *networkingv1beta1.Connection,
	value networkingv1beta1.ConnectionStatusValue, latency time.Duration, timestamp time.Time) error {
	var ts *metav1.Time
	if !timestamp.IsZero() {
		t := metav1.NewTime(timestamp)
		ts = &t
	}

	patch := &networkingv1beta1.Connection{
		TypeMeta: metav1.TypeMeta{
			APIVersion: networkingv1beta1.GroupVersion.String(),
			Kind:       networkingv1beta1.ConnectionKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      connection.Name,
			Namespace: connection.Namespace,
		},
		Status: networkingv1beta1.ConnectionStatus{
			Value: value,
			Latency: networkingv1beta1.ConnectionLatency{
				Value:     timeutils.FormatLatency(latency),
				Timestamp: ts,
			},
		},
	}
	//nolint:staticcheck // Keep SSA until ApplyConfiguration migration.
	if err := cl.Status().Patch(ctx, patch, client.Apply,
		client.FieldOwner(consts.CtrlConnectionAggregator),
		client.ForceOwnership,
	); err != nil {
		return fmt.Errorf("unable to patch aggregated connection status %q: %w",
			client.ObjectKeyFromObject(connection).String(), err)
	}

	return nil
}
