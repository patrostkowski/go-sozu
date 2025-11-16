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

package client

import "github.com/patrostkowski/go-sozu/internal"

type (
	Request  = internal.Request
	Response = internal.Response
)

// A simple socket address type your callers use.
type SocketAddress struct {
	Host string // "0.0.0.0"
	Port int    // 80
}

type ListenerType string

const (
	ListenerHTTP  ListenerType = "http"
	ListenerHTTPS ListenerType = "https"
	ListenerTCP   ListenerType = "tcp"
)

type HTTPListenerOptions struct {
	Address     SocketAddress
	PublicAddr  *SocketAddress
	ExpectProxy bool
	StickyName  string
	Active      bool
}

type HTTPSListenerOptions struct {
	Address     SocketAddress
	PublicAddr  *SocketAddress
	ExpectProxy bool
	StickyName  string // required for HTTPS
	Active      bool
}

type TCPListenerOptions struct {
	Address     SocketAddress
	PublicAddr  *SocketAddress
	ExpectProxy bool
	Active      bool
}

// Frontends
type PathMatchKind string

const (
	PathPrefix PathMatchKind = "prefix"
	PathRegex  PathMatchKind = "regex"
	PathEquals PathMatchKind = "equals"
)

type PathMatch struct {
	Value string
	Kind  PathMatchKind
}

type RulePosition string

const (
	RulePre  RulePosition = "pre"
	RulePost RulePosition = "post"
	RuleTree RulePosition = "tree"
)

type HTTPFrontendOptions struct {
	ClusterID string
	Address   SocketAddress
	Hostname  string
	Position  RulePosition
	Method    string
	Path      *PathMatch
}

// Add/remove variants can reuse the same types or slightly different ones,
// depending on how strict you want to be.
