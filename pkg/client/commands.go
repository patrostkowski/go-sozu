package client

import (
	"context"
	"fmt"

	internal "github.com/patrostkowski/go-sozu/internal"
)

// Status retrieves the current status information from the Sozu proxy.
// It performs a simple health/status check and returns the full `Response`
// message from Sozu.
func (c *Client) Status(ctx context.Context) (*internal.Response, error) {
	req := &internal.Request{
		RequestType: &internal.Request_Status{
			Status: &internal.Status{},
		},
	}
	return c.do(ctx, req)
}

// AddHttpListener registers a new HTTP listener in Sozu using the provided
// HttpListenerConfig. Returns an error if cfg is nil.
func (c *Client) AddHttpListener(ctx context.Context, cfg *internal.HttpListenerConfig) (*internal.Response, error) {
	if cfg == nil {
		return nil, fmt.Errorf("AddHttpListener: nil config")
	}
	req := &internal.Request{
		RequestType: &internal.Request_AddHttpListener{
			AddHttpListener: cfg,
		},
	}
	return c.do(ctx, req)
}

// AddHttpsListener registers a new HTTPS listener in Sozu using the provided
// HttpsListenerConfig. Returns an error if cfg is nil.
func (c *Client) AddHttpsListener(ctx context.Context, cfg *internal.HttpsListenerConfig) (*internal.Response, error) {
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

// AddTcpListener registers a new TCP listener in Sozu. Returns an error if cfg is nil.
func (c *Client) AddTcpListener(ctx context.Context, cfg *internal.TcpListenerConfig) (*internal.Response, error) {
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

// RemoveListener removes an existing listener identified by the socket address and type.
// Returns an error if the address is nil.
func (c *Client) RemoveListener(ctx context.Context, addr *internal.SocketAddress, proxy internal.ListenerType) (*internal.Response, error) {
	if addr == nil {
		return nil, fmt.Errorf("RemoveListener: nil address")
	}
	req := &internal.Request{
		RequestType: &internal.Request_RemoveListener{
			RemoveListener: &internal.RemoveListener{
				Address: addr,
				Proxy:   &proxy,
			},
		},
	}
	return c.do(ctx, req)
}

// ActivateListener enables a previously configured listener. If fromScm is true,
// Sozu will try to activate the listener using a socket passed from systemd/SCM.
func (c *Client) ActivateListener(ctx context.Context, addr *internal.SocketAddress, proxy internal.ListenerType, fromScm bool) (*internal.Response, error) {
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
func (c *Client) DeactivateListener(ctx context.Context, addr *internal.SocketAddress, proxy internal.ListenerType, toScm bool) (*internal.Response, error) {
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

// ListFrontends lists existing frontend configurations using optional filters.
// When filters are nil, all frontends are returned.
func (c *Client) ListFrontends(ctx context.Context, f *internal.FrontendFilters) (*internal.Response, error) {
	req := &internal.Request{
		RequestType: &internal.Request_ListFrontends{
			ListFrontends: f,
		},
	}
	return c.do(ctx, req)
}

// AddHttpFrontend creates and registers a new HTTP frontend definition.
// Returns an error if f is nil.
func (c *Client) AddHttpFrontend(ctx context.Context, f *internal.RequestHttpFrontend) (*internal.Response, error) {
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
// Returns an error if f is nil.
func (c *Client) RemoveHttpFrontend(ctx context.Context, f *internal.RequestHttpFrontend) (*internal.Response, error) {
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
// HTTPS frontends reuse RequestHttpFrontend (domains, paths, rules). Returns error on nil input.
func (c *Client) AddHttpsFrontend(ctx context.Context, f *internal.RequestHttpFrontend) (*internal.Response, error) {
	// Yes, HTTPS uses RequestHttpFrontend in the proto (domains, path rules, etc.)
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
// Returns an error if f is nil.
func (c *Client) RemoveHttpsFrontend(ctx context.Context, f *internal.RequestHttpFrontend) (*internal.Response, error) {
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

// AddTcpFrontend registers a new TCP frontend rule. Returns an error if f is nil.
func (c *Client) AddTcpFrontend(ctx context.Context, f *internal.RequestTcpFrontend) (*internal.Response, error) {
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
// Returns an error if f is nil.
func (c *Client) RemoveTcpFrontend(ctx context.Context, f *internal.RequestTcpFrontend) (*internal.Response, error) {
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
// Returns an error if the cluster definition is nil.
func (c *Client) AddCluster(ctx context.Context, cl *internal.Cluster) (*internal.Response, error) {
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

// RemoveCluster deletes a cluster by ID. Returns an error if the ID is empty.
func (c *Client) RemoveCluster(ctx context.Context, clusterID string) (*internal.Response, error) {
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
// Returns an error if the backend configuration is nil.
func (c *Client) AddBackend(ctx context.Context, b *internal.AddBackend) (*internal.Response, error) {
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
// Returns an error if the request object is nil.
func (c *Client) RemoveBackend(ctx context.Context, b *internal.RemoveBackend) (*internal.Response, error) {
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

// AddCertificate uploads a new TLS certificate+key pair to Sozu for use by HTTPS frontends.
// Returns an error if the request is nil.
func (c *Client) AddCertificate(ctx context.Context, reqCert *internal.AddCertificate) (*internal.Response, error) {
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
// Returns an error if the request is nil.
func (c *Client) ReplaceCertificate(ctx context.Context, reqCert *internal.ReplaceCertificate) (*internal.Response, error) {
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
// Returns an error if the request is nil.
func (c *Client) RemoveCertificate(ctx context.Context, reqCert *internal.RemoveCertificate) (*internal.Response, error) {
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
