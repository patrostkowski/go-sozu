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
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	pb "github.com/patrostkowski/go-sozu/pkg/pb"
	"google.golang.org/protobuf/proto"
)

const (
	SozuDefaultUnixSocketPath string = "/run/sozu/sozu.sock"
	SozuDefaultConfigPath     string = "/etc/sozu/config.toml"
	delimiterSize                    = 8
)

// Client is a Unix-socket-only Sōzu admin client.
type Client struct {
	socketPath string
	timeout    time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithTimeout sets the per-request timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.timeout = d
	}
}

// New creates a new Sōzu client.
func New(opts ...Option) *Client {
	c := &Client{
		socketPath: SozuDefaultUnixSocketPath,
		timeout:    10 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// do sends a Request protobuf to Sōzu and reads one Response protobuf.
func (c *Client) do(ctx context.Context, req *pb.Request) (*pb.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}

	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial unix %q: %w", c.socketPath, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	payload, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// message_len = delimiterSize + payload_len (matches Channel::write_delimited_message in channel.rs)
	messageLen := uint64(len(payload) + delimiterSize)

	header := make([]byte, delimiterSize)
	binary.LittleEndian.PutUint64(header, messageLen)

	// write header then payload
	if _, err := conn.Write(header); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("write payload: %w", err)
	}

	for {
		// first read 8-byte length
		respHeader := make([]byte, delimiterSize)
		if _, err := io.ReadFull(conn, respHeader); err != nil {
			return nil, fmt.Errorf("read response header: %w", err)
		}

		respMessageLen := binary.LittleEndian.Uint64(respHeader)
		if respMessageLen < delimiterSize {
			return nil, fmt.Errorf("invalid response length: %d", respMessageLen)
		}
		if respMessageLen > 10*1024*1024 {
			return nil, fmt.Errorf("response too large: %d bytes", respMessageLen)
		}

		// then read payload
		respPayloadLen := int(respMessageLen) - delimiterSize
		respBuf := make([]byte, respPayloadLen)
		if _, err := io.ReadFull(conn, respBuf); err != nil {
			return nil, fmt.Errorf("read response payload: %w", err)
		}

		var resp pb.Response
		if err := proto.Unmarshal(respBuf, &resp); err != nil {
			return nil, fmt.Errorf("unmarshal response: %w", err)
		}

		switch resp.GetStatus() {
		case pb.ResponseStatus_PROCESSING:
			// keep processing until ResponseStatus_OK
			continue
		case pb.ResponseStatus_FAILURE:
			return &resp, fmt.Errorf("sozu error: %s", resp.GetMessage())
		default:
			return &resp, nil
		}
	}
}
