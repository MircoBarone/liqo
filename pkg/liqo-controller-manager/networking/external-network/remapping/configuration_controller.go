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

package remapping

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	liqov1beta1 "github.com/liqotech/liqo/apis/core/v1beta1"
	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
	tunnel "github.com/liqotech/liqo/pkg/gateway/tunnel"
	route "github.com/liqotech/liqo/pkg/liqo-controller-manager/networking/external-network/route"
	networkingutils "github.com/liqotech/liqo/pkg/liqo-controller-manager/networking/utils"
)

// cluster-role
// +kubebuilder:rbac:groups=networking.liqo.io,resources=configurations,verbs=get;list;create;delete;update;watch
// +kubebuilder:rbac:groups=networking.liqo.io,resources=configurations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.liqo.io,resources=firewallconfigurations,verbs=get;list;create;delete;update;watch
// +kubebuilder:rbac:groups=networking.liqo.io,resources=firewallconfigurations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.liqo.io,resources=gatewayclients,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.liqo.io,resources=gatewayservers,verbs=get;list;watch

// RemappingReconciler updates the PublicKey resource used to establish the Wireguard configuration.
//
//nolint:revive // It is a standard name.
type RemappingReconciler struct {
	Client         client.Client
	Scheme         *runtime.Scheme
	EventsRecorder record.EventRecorder
	Options        *Options
}

// NewRemappingReconciler returns a new PublicKeysReconciler.
func NewRemappingReconciler(cl client.Client, s *runtime.Scheme, er record.EventRecorder) (*RemappingReconciler, error) {
	opts, err := NewOptions()
	if err != nil {
		return nil, fmt.Errorf("unable to create the RemappingReconciler: %w", err)
	}
	return &RemappingReconciler{
		Client:         cl,
		Scheme:         s,
		EventsRecorder: er,
		Options:        opts,
	}, nil
}

// Reconcile manage Configuration resources.
func (r *RemappingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	conf := &networkingv1beta1.Configuration{}
	if err := r.Client.Get(ctx, req.NamespacedName, conf); err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(6).Infof("There is no configuration %s", req.String())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get the configuration %q: %w", req.NamespacedName, err)
	}
	remoteClusterID := liqov1beta1.ClusterID(conf.Labels[string(consts.RemoteClusterID)])
	interfaces, err := route.GetGatewayInterfaces(ctx, r.Client, remoteClusterID)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to get gateway interfaces for configuration %q: %w", req.String(), err)
	}

	tunnelNames := make([]string, len(interfaces))
	for i := range interfaces {
		tunnelNames[i] = tunnel.GetTunnelName(i)
	}
	if err := CreateOrUpdateNatMappingCIDR(ctx, r.Client, r.Options, conf,
		r.Scheme, PodCIDR, tunnelNames); err != nil {
		return ctrl.Result{}, err
	}
	if err := CreateOrUpdateNatMappingCIDR(ctx, r.Client, r.Options, conf, r.Scheme, ExternalCIDR, tunnelNames); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager register the RemappingReconciler to the manager.
func (r *RemappingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).Named(consts.CtrlConfigurationRemapping).
		For(&networkingv1beta1.Configuration{}, builder.WithPredicates(networkingutils.AreConfigurationNetworkCIDRsConfiguredPredicate())).
		Watches(
			&networkingv1beta1.GatewayClient{},
			handler.EnqueueRequestsFromMapFunc(r.mapGatewayToConfiguration),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Watches(
			&networkingv1beta1.GatewayServer{},
			handler.EnqueueRequestsFromMapFunc(r.mapGatewayToConfiguration),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Complete(r)
}

// mapGatewayToConfiguration maps a GatewayClient/GatewayServer event to the Configuration
// sharing the same RemoteClusterID, so that a change in the number of interfaces
// re-triggers the NAT remapping logic even though the Configuration itself is unchanged.
func (r *RemappingReconciler) mapGatewayToConfiguration(ctx context.Context, obj client.Object) []reconcile.Request {
	remoteClusterID, ok := obj.GetLabels()[string(consts.RemoteClusterID)]
	if !ok {
		klog.V(4).Infof("object %q has no RemoteClusterID label, skipping", client.ObjectKeyFromObject(obj))
		return nil
	}

	confList := &networkingv1beta1.ConfigurationList{}
	if err := r.Client.List(ctx, confList,
		client.InNamespace(obj.GetNamespace()),
		client.MatchingLabels{string(consts.RemoteClusterID): remoteClusterID},
	); err != nil {
		klog.Errorf("unable to list configurations for remote cluster %q: %v", remoteClusterID, err)
		return nil
	}

	requests := make([]reconcile.Request, 0, len(confList.Items))
	for i := range confList.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&confList.Items[i]),
		})
	}
	return requests
}
