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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
)

// AggregatorReconciler coordinates the status aggregation across multiple tunnels.
type AggregatorReconciler struct {
	Client  client.Client
	Scheme  *runtime.Scheme
	Options *Options
}

// Reconcile triggers whenever a Connection resource changes.
func (r *AggregatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	connection := &networkingv1beta1.Connection{}
	if err := r.Client.Get(ctx, req.NamespacedName, connection); err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(4).Infof("Connection %s not found", req.String())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get connection %q: %w", req.NamespacedName, err)
	}

	tunnels := connection.Status.Tunnels
	expectedInterfaces := r.Options.GwOptions.NumInterfaces

	var totalLatency time.Duration
	var hasError bool
	var isConnecting bool

	if len(tunnels) < expectedInterfaces {
		klog.Warningf("Aggregator: invalid configuration or missing interfaces (expected %d, got %d). Forcing global Error status.",
			expectedInterfaces, len(tunnels))
		hasError = true
	}

	if !hasError {
		for i := range tunnels {
			switch tunnels[i].Value {
			case networkingv1beta1.ConnectionError:
				hasError = true

			case networkingv1beta1.Connecting:
				isConnecting = true

			case networkingv1beta1.Connected:
				parsedLatency, err := time.ParseDuration(tunnels[i].Latency.Value)
				if err != nil {
					klog.Warningf("Unable to parse latency %q for tunnel %s: %v",
						tunnels[i].Latency.Value, tunnels[i].InterfaceID, err)
					hasError = true
					break
				}
				totalLatency += parsedLatency
			}
		}
	}

	var globalValue networkingv1beta1.ConnectionStatusValue
	var globalLatency time.Duration
	var globalTimestamp time.Time

	switch {
	case hasError:
		globalValue = networkingv1beta1.ConnectionError
		globalLatency = 0
		globalTimestamp = time.Time{}

	case isConnecting:
		globalValue = networkingv1beta1.Connecting
		globalLatency = 0
		globalTimestamp = time.Now()

	default:
		globalValue = networkingv1beta1.Connected

		if expectedInterfaces > 0 {
			globalLatency = time.Duration(totalLatency.Nanoseconds() / int64(expectedInterfaces))
		} else {
			globalLatency = 0
		}

		globalTimestamp = time.Now()
	}

	err := UpdateConnectionStatusAggregated(
		ctx,
		r.Client,
		connection,
		globalValue,
		globalLatency,
		globalTimestamp,
	)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to update aggregated connection status: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the Aggregator to the manager.
func (r *AggregatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	filterByLabelsPredicate, err := predicate.LabelSelectorPredicate(metav1.LabelSelector{
		MatchLabels: map[string]string{
			string(consts.RemoteClusterID): r.Options.GwOptions.RemoteClusterID,
		},
	})
	if err != nil {
		return err
	}

	filterByTunnelMetricsPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldConn := e.ObjectOld.(*networkingv1beta1.Connection)
			newConn := e.ObjectNew.(*networkingv1beta1.Connection)

			if !newConn.DeletionTimestamp.IsZero() {
				return false
			}

			return !tunnelsAreEqual(oldConn.Status.Tunnels, newConn.Status.Tunnels)
		},
		CreateFunc: func(_ event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(_ event.DeleteEvent) bool {
			return false
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(consts.CtrlConnectionAggregator).
		For(&networkingv1beta1.Connection{}, builder.WithPredicates(predicate.And(filterByLabelsPredicate, filterByTunnelMetricsPredicate))).
		Complete(r)
}

// tunnelsAreEqual compares only the state and performance metrics of the tunnels.
// It deliberately ignores timestamps to prevent infinite reconciles.
func tunnelsAreEqual(oldTunnels, newTunnels []networkingv1beta1.TunnelStatus) bool {
	if len(oldTunnels) != len(newTunnels) {
		klog.Infof("tunnelsAreEqual: length mismatch (%d vs %d)", len(oldTunnels), len(newTunnels))
		return false
	}
	oldByID := make(map[string]networkingv1beta1.TunnelStatus, len(oldTunnels))
	for _, t := range oldTunnels {
		oldByID[t.InterfaceID] = t
	}

	for _, newT := range newTunnels {
		oldT, ok := oldByID[newT.InterfaceID]
		if !ok || oldT.Value != newT.Value || oldT.Latency.Value != newT.Latency.Value {
			return false
		}
	}
	return true
}
