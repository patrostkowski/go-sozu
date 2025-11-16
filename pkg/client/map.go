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

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	internal "github.com/patrostkowski/go-sozu/internal"
)

func toPBSocketAddress(a SocketAddress) (*internal.SocketAddress, error) {
	ip := net.ParseIP(a.Host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", a.Host)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 supported (got %q)", a.Host)
	}

	if a.Port <= 0 || a.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d", a.Port)
	}
	port := uint32(a.Port)

	v4 := binary.BigEndian.Uint32(ip4)
	return &internal.SocketAddress{
		Ip: &internal.IpAddress{
			Inner: &internal.IpAddress_V4{V4: v4},
		},
		Port: &port,
	}, nil
}

func toPBPathRuleKind(k PathMatchKind) (internal.PathRuleKind, error) {
	switch strings.ToLower(string(k)) {
	case "", "prefix":
		return internal.PathRuleKind_PREFIX, nil
	case "regex":
		return internal.PathRuleKind_REGEX, nil
	case "equals":
		return internal.PathRuleKind_EQUALS, nil
	default:
		return 0, fmt.Errorf("unknown path match kind %q", k)
	}
}

func toPBRulePosition(p RulePosition) (internal.RulePosition, error) {
	switch strings.ToLower(string(p)) {
	case "", "pre":
		return internal.RulePosition_PRE, nil
	case "post":
		return internal.RulePosition_POST, nil
	case "tree":
		return internal.RulePosition_TREE, nil
	default:
		return 0, fmt.Errorf("unknown rule position %q", p)
	}
}
