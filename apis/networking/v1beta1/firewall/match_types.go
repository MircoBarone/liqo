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

package firewall

// MatchOperation is the operation of the match.
type MatchOperation string

const (
	// MatchOperationEq is the equality operation
	// (can be used with IP, Port, Proto, Dev).
	MatchOperationEq MatchOperation = "eq"
	// MatchOperationNeq is the inequality operation
	// (can be used for IP, Port, Proto, Dev).
	MatchOperationNeq MatchOperation = "neq"
	// MatchOperationIn indicates the element must be part of the set.
	// (Use only with Set)
	MatchOperationIn MatchOperation = "in"
	// MatchOperationNin indicates the element must not be part of the set.
	// (Use only with Set)
	MatchOperationNin MatchOperation = "nin"
)

// MatchPosition is the position of the IP in the packet.
type MatchPosition string

const (
	// MatchPositionSrc is the position of the IP in the packet.
	MatchPositionSrc MatchPosition = "src"
	// MatchPositionDst is the position of the IP in the packet.
	MatchPositionDst MatchPosition = "dst"
)

// MatchDevPosition is the position of the device in the packet.
type MatchDevPosition string

const (
	// MatchDevPositionIn is the position of the device in the packet.
	MatchDevPositionIn MatchDevPosition = "in"
	// MatchDevPositionOut is the position of the device in the packet.
	MatchDevPositionOut MatchDevPosition = "out"
)

// L4Proto is the protocol of the packet.
type L4Proto string

const (
	// L4ProtoTCP is the protocol of the packet.
	L4ProtoTCP L4Proto = "tcp"
	// L4ProtoUDP is the protocol of the packet.
	L4ProtoUDP L4Proto = "udp"
)

// MatchIP is an IP to be matched.
// +kubebuilder:object:generate=true
type MatchIP struct {
	// Value is the IP or a Subnet to be matched.
	Value string `json:"value"`
	// Position is the position of the IP in the packet.
	// +kubebuilder:validation:Enum=src;dst
	Position MatchPosition `json:"position"`
}

// MatchPort is a port to be matched.
// +kubebuilder:object:generate=true
type MatchPort struct {
	// Value is the port or a range (eg. 3000-4000) to be matched.
	Value string `json:"value"`
	// Position is the position of the port in the packet.
	// +kubebuilder:validation:Enum=src;dst
	Position MatchPosition `json:"position"`
}

// MatchDev is a device to be matched.
// +kubebuilder:object:generate=true
type MatchDev struct {
	// Value is the name of the device to be matched.
	Value string `json:"value"`
	// Position is the source device of the packet.
	// +kubebuilder:validation:Enum=in;out
	Position MatchDevPosition `json:"position"`
}

// MatchProto is a protocol to be matched.
// +kubebuilder:object:generate=true
type MatchProto struct {
	// Value is the protocol to be matched.
	// +kubebuilder:validation:Enum=tcp;udp
	Value L4Proto `json:"value"`
}

// MatchSet is a set of devices to be matched.
// It is an extensions of MatchDev struct
// +kubebuilder:object:generate=true
type MatchSet struct {
	// Values are the names of the device to be matched.
	Values []string `json:"values"`
	// Position is the source device of the packet. (in or out)
	// +kubebuilder:validation:Enum=in;out
	Position MatchDevPosition `json:"position"`
}

// Match is a match to be applied to a rule.
// +kubebuilder:object:generate=true
type Match struct {
	// Op is the operation of the match.
	// Use 'eq'/'neq' for IP, Port, Proto, Dev. Use 'in'/'nin' for Set.
	// +kubebuilder:validation:Enum=eq;neq;in;nin
	Op MatchOperation `json:"op"`
	// IP contains the options to match an IP or a Subnet.
	IP *MatchIP `json:"ip,omitempty"`
	// Port contains the options to match a port.
	Port *MatchPort `json:"port,omitempty"`
	// Proto contains the options to match a protocol.
	Proto *MatchProto `json:"proto,omitempty"`
	// Dev contains the options to match a device.
	Dev *MatchDev `json:"dev,omitempty"`
	// Set contains the options to match a set of devices.
	Set *MatchSet `json:"set,omitempty"`
}
