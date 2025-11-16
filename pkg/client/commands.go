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
	"fmt"

	internal "github.com/patrostkowski/go-sozu/internal"
)

// Status retrieves the current status information from the Sozu proxy.
// It performs a simple health/status check and returns the full `Response`
// message from Sozu.
func (c *Client) Status(ctx context.Context) (*Response, error) {
	req := &internal.Request{
		RequestType: &internal.Request_Status{
			Status: &internal.Status{},
		},
	}
	return c.do(ctx, req)
}

func (c *Client) ListListeners(ctx context.Context) (*Response, error) {
	req := &internal.Request{
		RequestType: &internal.Request_ListListeners{
			ListListeners: &internal.ListListeners{},
		},
	}
	return c.do(ctx, req)
}

// ListFrontends lists existing frontends using optional filters.
// When filters is nil, all frontends are returned.
func (c *Client) ListFrontends(ctx context.Context, filters *internal.FrontendFilters) (*Response, error) {
	req := &internal.Request{
		RequestType: &internal.Request_ListFrontends{
			ListFrontends: filters,
		},
	}
	return c.do(ctx, req)
}

// AddHttpListener registers a new HTTP listener in Sozu using the provided
// HttpListenerConfig. Returns an error if cfg is nil.
func (c *Client) AddHttpListener(ctx context.Context, opts HTTPListenerOptions) (*Response, error) {
	var cfg internal.HttpListenerConfig
	var err error

	cfg.Address, err = toPBSocketAddress(opts.Address)
	if err != nil {
		return nil, err
	}

	if opts.PublicAddr != nil {
		pub, err := toPBSocketAddress(*opts.PublicAddr)
		if err != nil {
			return nil, err
		}
		cfg.PublicAddress = pub
	}
	if opts.StickyName == "" {
		return nil, fmt.Errorf("StickyName is required")
	}
	cfg.StickyName = &opts.StickyName
	cfg.ExpectProxy = &opts.ExpectProxy
	cfg.Active = &opts.Active

	ft := internal.Default_HttpListenerConfig_FrontTimeout
	bt := internal.Default_HttpListenerConfig_BackTimeout
	ct := internal.Default_HttpListenerConfig_ConnectTimeout
	rt := internal.Default_HttpListenerConfig_RequestTimeout

	cfg.FrontTimeout = &ft
	cfg.BackTimeout = &bt
	cfg.ConnectTimeout = &ct
	cfg.RequestTimeout = &rt

	req := &internal.Request{
		RequestType: &internal.Request_AddHttpListener{
			AddHttpListener: &cfg,
		},
	}
	return c.do(ctx, req)
}

// RemoveHttpListener removes an HTTP listener for the given address.
func (c *Client) RemoveListener(ctx context.Context, addr SocketAddress) (*Response, error) {
	pbAddr, err := toPBSocketAddress(addr)
	if err != nil {
		return nil, err
	}

	proxy := internal.ListenerType_HTTP

	req := &internal.Request{
		RequestType: &internal.Request_RemoveListener{
			RemoveListener: &internal.RemoveListener{
				Address: pbAddr,
				Proxy:   &proxy,
			},
		},
	}

	return c.do(ctx, req)
}

// ListWorkers lists all workers.
func (c *Client) ListWorkers(ctx context.Context) (*Response, error) {
	req := &internal.Request{
		RequestType: &internal.Request_ListWorkers{
			ListWorkers: &internal.ListWorkers{},
		},
	}
	return c.do(ctx, req)
}

// AddHttpsListener registers a new HTTPS listener.
// You pass in the generated config directly – useful for internal/CLI usage.
func (c *Client) AddHttpsListener(ctx context.Context, cfg *internal.HttpsListenerConfig) (*Response, error) {
	if cfg == nil {
		return nil, fmt.Errorf("AddHttpsListener: nil config")
	}
	req := &internal.Request{
		RequestType: &internal.Request_AddHttpsListener{
			AddHttpsListener: cfg,
		},
	}
	return c.do(ctx, req)
}

// AddTcpListener registers a new TCP listener.
func (c *Client) AddTcpListener(ctx context.Context, cfg *internal.TcpListenerConfig) (*Response, error) {
	if cfg == nil {
		return nil, fmt.Errorf("AddTcpListener: nil config")
	}
	req := &internal.Request{
		RequestType: &internal.Request_AddTcpListener{
			AddTcpListener: cfg,
		},
	}
	return c.do(ctx, req)
}

// ActivateListener enables a previously configured listener. If fromScm is true,
// Sozu will try to activate the listener using a socket passed from systemd/SCM.
func (c *Client) ActivateListener(ctx context.Context, addr *internal.SocketAddress, proxy internal.ListenerType, fromScm bool) (*Response, error) {
	if addr == nil {
		return nil, fmt.Errorf("ActivateListener: nil address")
	}
	req := &internal.Request{
		RequestType: &internal.Request_ActivateListener{
			ActivateListener: &internal.ActivateListener{
				Address: addr,
				Proxy:   &proxy,
				FromScm: &fromScm,
			},
		},
	}
	return c.do(ctx, req)
}

// DeactivateListener disables a listener. If toScm is true,
// the underlying socket may be transferred back to systemd/SCM.
func (c *Client) DeactivateListener(ctx context.Context, addr *internal.SocketAddress, proxy internal.ListenerType, toScm bool) (*Response, error) {
	if addr == nil {
		return nil, fmt.Errorf("DeactivateListener: nil address")
	}
	req := &internal.Request{
		RequestType: &internal.Request_DeactivateListener{
			DeactivateListener: &internal.DeactivateListener{
				Address: addr,
				Proxy:   &proxy,
				ToScm:   &toScm,
			},
		},
	}
	return c.do(ctx, req)
}

// AddHttpFrontend creates and registers a new HTTP frontend definition.
// This uses the raw protobuf type for now.
func (c *Client) AddHttpFrontend(ctx context.Context, f *internal.RequestHttpFrontend) (*Response, error) {
	if f == nil {
		return nil, fmt.Errorf("AddHttpFrontend: nil frontend")
	}
	req := &internal.Request{
		RequestType: &internal.Request_AddHttpFrontend{
			AddHttpFrontend: f,
		},
	}
	return c.do(ctx, req)
}

// RemoveHttpFrontend removes a previously configured HTTP frontend.
func (c *Client) RemoveHttpFrontend(ctx context.Context, f *internal.RequestHttpFrontend) (*Response, error) {
	if f == nil {
		return nil, fmt.Errorf("RemoveHttpFrontend: nil frontend")
	}
	req := &internal.Request{
		RequestType: &internal.Request_RemoveHttpFrontend{
			RemoveHttpFrontend: f,
		},
	}
	return c.do(ctx, req)
}

// AddHttpsFrontend creates and registers a new HTTPS frontend.
// HTTPS frontends reuse RequestHttpFrontend (domains, path rules, etc.).
func (c *Client) AddHttpsFrontend(ctx context.Context, f *internal.RequestHttpFrontend) (*Response, error) {
	if f == nil {
		return nil, fmt.Errorf("AddHttpsFrontend: nil frontend")
	}
	req := &internal.Request{
		RequestType: &internal.Request_AddHttpsFrontend{
			AddHttpsFrontend: f,
		},
	}
	return c.do(ctx, req)
}

// RemoveHttpsFrontend removes a configured HTTPS frontend.
func (c *Client) RemoveHttpsFrontend(ctx context.Context, f *internal.RequestHttpFrontend) (*Response, error) {
	if f == nil {
		return nil, fmt.Errorf("RemoveHttpsFrontend: nil frontend")
	}
	req := &internal.Request{
		RequestType: &internal.Request_RemoveHttpsFrontend{
			RemoveHttpsFrontend: f,
		},
	}
	return c.do(ctx, req)
}

// AddTcpFrontend registers a new TCP frontend rule.
func (c *Client) AddTcpFrontend(ctx context.Context, f *internal.RequestTcpFrontend) (*Response, error) {
	if f == nil {
		return nil, fmt.Errorf("AddTcpFrontend: nil frontend")
	}
	req := &internal.Request{
		RequestType: &internal.Request_AddTcpFrontend{
			AddTcpFrontend: f,
		},
	}
	return c.do(ctx, req)
}

// RemoveTcpFrontend removes a TCP frontend configuration.
func (c *Client) RemoveTcpFrontend(ctx context.Context, f *internal.RequestTcpFrontend) (*Response, error) {
	if f == nil {
		return nil, fmt.Errorf("RemoveTcpFrontend: nil frontend")
	}
	req := &internal.Request{
		RequestType: &internal.Request_RemoveTcpFrontend{
			RemoveTcpFrontend: f,
		},
	}
	return c.do(ctx, req)
}

// AddCluster registers a new cluster backend pool in Sozu.
func (c *Client) AddCluster(ctx context.Context, cl *internal.Cluster) (*Response, error) {
	if cl == nil {
		return nil, fmt.Errorf("AddCluster: nil cluster")
	}
	req := &internal.Request{
		RequestType: &internal.Request_AddCluster{
			AddCluster: cl,
		},
	}
	return c.do(ctx, req)
}

// RemoveCluster deletes a cluster by ID.
func (c *Client) RemoveCluster(ctx context.Context, clusterID string) (*Response, error) {
	if clusterID == "" {
		return nil, fmt.Errorf("RemoveCluster: empty clusterID")
	}
	req := &internal.Request{
		RequestType: &internal.Request_RemoveCluster{
			RemoveCluster: clusterID,
		},
	}
	return c.do(ctx, req)
}

// AddBackend adds a backend server to an existing cluster.
func (c *Client) AddBackend(ctx context.Context, b *internal.AddBackend) (*Response, error) {
	if b == nil {
		return nil, fmt.Errorf("AddBackend: nil backend")
	}
	req := &internal.Request{
		RequestType: &internal.Request_AddBackend{
			AddBackend: b,
		},
	}
	return c.do(ctx, req)
}

// RemoveBackend removes a backend from a cluster.
func (c *Client) RemoveBackend(ctx context.Context, b *internal.RemoveBackend) (*Response, error) {
	if b == nil {
		return nil, fmt.Errorf("RemoveBackend: nil backend")
	}
	req := &internal.Request{
		RequestType: &internal.Request_RemoveBackend{
			RemoveBackend: b,
		},
	}
	return c.do(ctx, req)
}

// AddCertificate uploads a new TLS certificate+key pair to Sozu.
func (c *Client) AddCertificate(ctx context.Context, reqCert *internal.AddCertificate) (*Response, error) {
	if reqCert == nil {
		return nil, fmt.Errorf("AddCertificate: nil request")
	}
	req := &internal.Request{
		RequestType: &internal.Request_AddCertificate{
			AddCertificate: reqCert,
		},
	}
	return c.do(ctx, req)
}

// ReplaceCertificate updates an existing certificate with a new certificate+key.
func (c *Client) ReplaceCertificate(ctx context.Context, reqCert *internal.ReplaceCertificate) (*Response, error) {
	if reqCert == nil {
		return nil, fmt.Errorf("ReplaceCertificate: nil request")
	}
	req := &internal.Request{
		RequestType: &internal.Request_ReplaceCertificate{
			ReplaceCertificate: reqCert,
		},
	}
	return c.do(ctx, req)
}

// RemoveCertificate deletes a certificate from the Sozu configuration.
func (c *Client) RemoveCertificate(ctx context.Context, reqCert *internal.RemoveCertificate) (*Response, error) {
	if reqCert == nil {
		return nil, fmt.Errorf("RemoveCertificate: nil request")
	}
	req := &internal.Request{
		RequestType: &internal.Request_RemoveCertificate{
			RemoveCertificate: reqCert,
		},
	}
	return c.do(ctx, req)
}
