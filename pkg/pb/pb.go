// Copyright 2025 Patryk Rostkowski
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pb

// Package pb exposes selected protobuf types used by go-sozu.
// NOTE: This is intentionally a "low-level" API. For typical usage, prefer
// the higher-level helpers in pkg/client.

import internal "github.com/patrostkowski/go-sozu/internal"

// Core request/response types.
type (
	Request  = internal.Request
	Response = internal.Response
)

// Common content / config types.
type (
	Status              = internal.Status
	FrontendFilters     = internal.FrontendFilters
	HttpListenerConfig  = internal.HttpListenerConfig
	HttpsListenerConfig = internal.HttpsListenerConfig
	TcpListenerConfig   = internal.TcpListenerConfig
	RequestHttpFrontend = internal.RequestHttpFrontend
	RequestTcpFrontend  = internal.RequestTcpFrontend
	Cluster             = internal.Cluster
	AddBackend          = internal.AddBackend
	RemoveBackend       = internal.RemoveBackend

	SocketAddress      = internal.SocketAddress
	IpAddress          = internal.IpAddress
	PathRule           = internal.PathRule
	CertificateAndKey  = internal.CertificateAndKey
	AddCertificate     = internal.AddCertificate
	ReplaceCertificate = internal.ReplaceCertificate
	RemoveCertificate  = internal.RemoveCertificate
)

// Enums.
type (
	ResponseStatus          = internal.ResponseStatus
	ListenerType            = internal.ListenerType
	RulePosition            = internal.RulePosition
	PathRuleKind            = internal.PathRuleKind
	ProxyProtocolConfig     = internal.ProxyProtocolConfig
	LoadBalancingAlgorithms = internal.LoadBalancingAlgorithms
	LoadMetric              = internal.LoadMetric
	TlsVersion              = internal.TlsVersion
)

// Re-export enum values that are likely useful to callers.
// (This keeps users from having to import the internal package just for consts.)

const (
	// ResponseStatus
	ResponseStatus_OK         = internal.ResponseStatus_OK
	ResponseStatus_FAILURE    = internal.ResponseStatus_FAILURE
	ResponseStatus_PROCESSING = internal.ResponseStatus_PROCESSING

	// ListenerType
	ListenerType_HTTP  = internal.ListenerType_HTTP
	ListenerType_HTTPS = internal.ListenerType_HTTPS
	ListenerType_TCP   = internal.ListenerType_TCP

	// RulePosition
	RulePosition_PRE  = internal.RulePosition_PRE
	RulePosition_POST = internal.RulePosition_POST
	RulePosition_TREE = internal.RulePosition_TREE

	// PathRuleKind
	PathRuleKind_PREFIX = internal.PathRuleKind_PREFIX
	PathRuleKind_REGEX  = internal.PathRuleKind_REGEX
	PathRuleKind_EQUALS = internal.PathRuleKind_EQUALS

	// ProxyProtocolConfig
	ProxyProtocolConfig_EXPECT_HEADER = internal.ProxyProtocolConfig_EXPECT_HEADER
	ProxyProtocolConfig_SEND_HEADER   = internal.ProxyProtocolConfig_SEND_HEADER
	ProxyProtocolConfig_RELAY_HEADER  = internal.ProxyProtocolConfig_RELAY_HEADER

	// LoadBalancingAlgorithms
	LoadBalancingAlgorithms_ROUND_ROBIN  = internal.LoadBalancingAlgorithms_ROUND_ROBIN
	LoadBalancingAlgorithms_RANDOM       = internal.LoadBalancingAlgorithms_RANDOM
	LoadBalancingAlgorithms_LEAST_LOADED = internal.LoadBalancingAlgorithms_LEAST_LOADED
	LoadBalancingAlgorithms_POWER_OF_TWO = internal.LoadBalancingAlgorithms_POWER_OF_TWO

	// LoadMetric
	LoadMetric_CONNECTIONS     = internal.LoadMetric_CONNECTIONS
	LoadMetric_REQUESTS        = internal.LoadMetric_REQUESTS
	LoadMetric_CONNECTION_TIME = internal.LoadMetric_CONNECTION_TIME

	// TlsVersion
	TlsVersion_SSL_V2   = internal.TlsVersion_SSL_V2
	TlsVersion_SSL_V3   = internal.TlsVersion_SSL_V3
	TlsVersion_TLS_V1_0 = internal.TlsVersion_TLS_V1_0
	TlsVersion_TLS_V1_1 = internal.TlsVersion_TLS_V1_1
	TlsVersion_TLS_V1_2 = internal.TlsVersion_TLS_V1_2
	TlsVersion_TLS_V1_3 = internal.TlsVersion_TLS_V1_3
)
