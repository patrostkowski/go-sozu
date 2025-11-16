package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	sozuinternal "github.com/patrostkowski/go-sozu/internal"
	sozuclient "github.com/patrostkowski/go-sozu/pkg/client"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	flagTimeout time.Duration
	flagOutput  string // "json" or "text"
)

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sozuctl",
		Short: "sozuctl is a CLI for the sozu proxy (using go-sozu)",
	}

	cmd.PersistentFlags().DurationVar(&flagTimeout, "timeout", 5*time.Second, "request timeout")
	cmd.PersistentFlags().StringVar(&flagOutput, "output", "text", "output format: text|json")

	// Core
	cmd.AddCommand(newStatusCmd())

	// Groups
	cmd.AddCommand(newListenersCmd())
	cmd.AddCommand(newFrontendsCmd())
	cmd.AddCommand(newClustersCmd())
	cmd.AddCommand(newBackendsCmd())
	cmd.AddCommand(newCertificatesCmd())
	cmd.AddCommand(newWorkersCmd())

	return cmd
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func newClient() *sozuclient.Client {
	return sozuclient.New()
}

func contextWithTimeout() (context.Context, context.CancelFunc) {
	if flagTimeout <= 0 {
		return context.Background(), func() {}
	}
	return context.WithTimeout(context.Background(), flagTimeout)
}

// printResponse prints a client.Response (alias of internal.Response).
func printResponse(resp *sozuclient.Response) {
	if resp == nil {
		fmt.Println("no response")
		return
	}

	if flagOutput == "json" {
		m := protojson.MarshalOptions{
			Multiline:       true,
			Indent:          "  ",
			UseEnumNumbers:  false,
			EmitUnpopulated: true,
		}
		b, err := m.Marshal(resp)
		if err != nil {
			log.Printf("failed to marshal response as json: %v", err)
			fmt.Printf("status=%s message=%s\n", resp.GetStatus(), resp.GetMessage())
			return
		}
		fmt.Println(string(b))
		return
	}

	fmt.Printf("Status:  %s\n", resp.GetStatus())
	fmt.Printf("Message: %s\n", resp.GetMessage())
	if c := resp.GetContent(); c != nil {
		m := protojson.MarshalOptions{
			Multiline:      true,
			Indent:         "  ",
			UseEnumNumbers: false,
		}
		b, err := m.Marshal(c)
		if err != nil {
			fmt.Printf("Content: %+v\n", c)
		} else {
			fmt.Printf("Content:\n%s\n", string(b))
		}
	}
}

// High-level address (for client APIs)
func parseSocketAddress(addr string) (sozuclient.SocketAddress, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return sozuclient.SocketAddress{}, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return sozuclient.SocketAddress{}, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	if port <= 0 || port > 65535 {
		return sozuclient.SocketAddress{}, fmt.Errorf("port must be in range 1-65535 (got %d)", port)
	}
	return sozuclient.SocketAddress{
		Host: host,
		Port: port,
	}, nil
}

// Protobuf SocketAddress (for internal types)
func parseInternalSocketAddress(addr string) (*sozuinternal.SocketAddress, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip %q", host)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 supported for now (got %q)", host)
	}

	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	if port64 == 0 {
		return nil, fmt.Errorf("port must be > 0")
	}
	port := uint32(port64)

	v4 := binary.BigEndian.Uint32(ip4)
	ipAddr := &sozuinternal.IpAddress{
		Inner: &sozuinternal.IpAddress_V4{V4: v4},
	}

	return &sozuinternal.SocketAddress{
		Ip:   ipAddr,
		Port: &port,
	}, nil
}

func parseRulePosition(s string) (sozuinternal.RulePosition, error) {
	switch strings.ToLower(s) {
	case "pre", "":
		return sozuinternal.RulePosition_PRE, nil
	case "post":
		return sozuinternal.RulePosition_POST, nil
	case "tree":
		return sozuinternal.RulePosition_TREE, nil
	default:
		return 0, fmt.Errorf("invalid rule position %q (pre|post|tree)", s)
	}
}

func parsePathRuleKind(s string) (sozuinternal.PathRuleKind, error) {
	switch strings.ToLower(s) {
	case "prefix", "":
		return sozuinternal.PathRuleKind_PREFIX, nil
	case "regex":
		return sozuinternal.PathRuleKind_REGEX, nil
	case "equals":
		return sozuinternal.PathRuleKind_EQUALS, nil
	default:
		return 0, fmt.Errorf("invalid path rule kind %q (prefix|regex|equals)", s)
	}
}

func parseProxyProtocolConfig(s string) (sozuinternal.ProxyProtocolConfig, error) {
	switch strings.ToLower(s) {
	case "", "none":
		return 0, nil
	case "expect_header":
		return sozuinternal.ProxyProtocolConfig_EXPECT_HEADER, nil
	case "send_header":
		return sozuinternal.ProxyProtocolConfig_SEND_HEADER, nil
	case "relay_header":
		return sozuinternal.ProxyProtocolConfig_RELAY_HEADER, nil
	default:
		return 0, fmt.Errorf("invalid proxy-protocol %q (expect_header|send_header|relay_header|none)", s)
	}
}

func parseLoadBalancing(s string) (sozuinternal.LoadBalancingAlgorithms, error) {
	switch strings.ToLower(s) {
	case "", "round_robin":
		return sozuinternal.LoadBalancingAlgorithms_ROUND_ROBIN, nil
	case "random":
		return sozuinternal.LoadBalancingAlgorithms_RANDOM, nil
	case "least_loaded":
		return sozuinternal.LoadBalancingAlgorithms_LEAST_LOADED, nil
	case "power_of_two":
		return sozuinternal.LoadBalancingAlgorithms_POWER_OF_TWO, nil
	default:
		return 0, fmt.Errorf("invalid load-balancing %q (round_robin|random|least_loaded|power_of_two)", s)
	}
}

func parseLoadMetric(s string) (sozuinternal.LoadMetric, error) {
	switch strings.ToLower(s) {
	case "", "connections":
		return sozuinternal.LoadMetric_CONNECTIONS, nil
	case "requests":
		return sozuinternal.LoadMetric_REQUESTS, nil
	case "connection_time":
		return sozuinternal.LoadMetric_CONNECTION_TIME, nil
	default:
		return 0, fmt.Errorf("invalid load-metric %q (connections|requests|connection_time)", s)
	}
}

func readFileAsString(path string) (string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func tlsVersionFromString(s string) (sozuinternal.TlsVersion, error) {
	switch strings.ToLower(s) {
	case "ssl_v2", "ssl2":
		return sozuinternal.TlsVersion_SSL_V2, nil
	case "ssl_v3", "ssl3":
		return sozuinternal.TlsVersion_SSL_V3, nil
	case "tls_v1_0", "tls1.0", "tls10":
		return sozuinternal.TlsVersion_TLS_V1_0, nil
	case "tls_v1_1", "tls1.1", "tls11":
		return sozuinternal.TlsVersion_TLS_V1_1, nil
	case "tls_v1_2", "tls1.2", "tls12":
		return sozuinternal.TlsVersion_TLS_V1_2, nil
	case "tls_v1_3", "tls1.3", "tls13":
		return sozuinternal.TlsVersion_TLS_V1_3, nil
	default:
		return 0, fmt.Errorf("invalid TLS version %q", s)
	}
}

func buildCertAndKey(certFile, keyFile string, names []string, versions []string) (*sozuinternal.CertificateAndKey, error) {
	if certFile == "" {
		return nil, fmt.Errorf("--cert-file is required")
	}
	if keyFile == "" {
		return nil, fmt.Errorf("--key-file is required")
	}

	certPEM, err := readFileAsString(certFile)
	if err != nil {
		return nil, fmt.Errorf("read cert-file: %w", err)
	}
	keyPEM, err := readFileAsString(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read key-file: %w", err)
	}

	ck := &sozuinternal.CertificateAndKey{
		Certificate: &certPEM,
		Key:         &keyPEM,
	}

	if len(names) > 0 {
		ck.Names = append(ck.Names, names...)
	}

	for _, v := range versions {
		if v == "" {
			continue
		}
		tv, err := tlsVersionFromString(v)
		if err != nil {
			return nil, err
		}
		ck.Versions = append(ck.Versions, tv)
	}

	return ck, nil
}

// -----------------------------------------------------------------------------
// status
// -----------------------------------------------------------------------------

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show Sozu status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.Status(ctx)
			if err != nil {
				return fmt.Errorf("status: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}
}

// -----------------------------------------------------------------------------
// listeners group
// -----------------------------------------------------------------------------

func newListenersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "listeners",
		Short: "Manage listeners (HTTP/HTTPS/TCP)",
	}

	cmd.AddCommand(newListenersAddHTTPCmd())
	cmd.AddCommand(newListenersListCmd())
	cmd.AddCommand(newListenersDeleteHTTPCmd())

	return cmd
}

// sozuctl listeners add-http
func newListenersAddHTTPCmd() *cobra.Command {
	var (
		addrStr       string
		publicAddrStr string
		expectProxy   bool
		active        bool
		stickyName    string
	)

	cmd := &cobra.Command{
		Use:   "add-http",
		Short: "Add an HTTP listener",
		RunE: func(cmd *cobra.Command, args []string) error {
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ex: 0.0.0.0:80)")
			}
			if stickyName == "" {
				return fmt.Errorf("--sticky-name is required for HTTP listener")
			}

			addr, err := parseSocketAddress(addrStr)
			if err != nil {
				return err
			}

			opts := sozuclient.HTTPListenerOptions{
				Address:     addr,
				ExpectProxy: expectProxy,
				StickyName:  stickyName,
				Active:      active,
			}

			if publicAddrStr != "" {
				pub, err := parseSocketAddress(publicAddrStr)
				if err != nil {
					return fmt.Errorf("public-addr: %w", err)
				}
				opts.PublicAddr = &pub
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.AddHttpListener(ctx, opts)
			if err != nil {
				return fmt.Errorf("AddHttpListener: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&addrStr, "addr", "", "listener address (ip:port)")
	cmd.Flags().StringVar(&publicAddrStr, "public-addr", "", "optional public address (ip:port)")
	cmd.Flags().BoolVar(&expectProxy, "expect-proxy", false, "expect PROXY protocol header")
	cmd.Flags().BoolVar(&active, "active", true, "start listener as active")
	cmd.Flags().StringVar(&stickyName, "sticky-name", "", "sticky session cookie name")

	return cmd
}

// sozuctl listeners list
func newListenersListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all listeners (HTTP/HTTPS/TCP)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.ListListeners(ctx)
			if err != nil {
				return fmt.Errorf("ListListeners: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}
	return cmd
}

// sozuctl listeners delete-http
func newListenersDeleteHTTPCmd() *cobra.Command {
	var addrStr string

	cmd := &cobra.Command{
		Use:   "delete-http",
		Short: "Remove an HTTP listener",
		RunE: func(cmd *cobra.Command, args []string) error {
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}

			addr, err := parseSocketAddress(addrStr)
			if err != nil {
				return err
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.RemoveListener(ctx, addr)
			if err != nil {
				return fmt.Errorf("RemoveHttpListener: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&addrStr, "addr", "", "listener address (ip:port)")
	return cmd
}

// -----------------------------------------------------------------------------
// frontends group
// -----------------------------------------------------------------------------

func newFrontendsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "frontends",
		Short: "Manage frontends (HTTP/HTTPS/TCP)",
	}

	cmd.AddCommand(newFrontendsListCmd())
	cmd.AddCommand(newFrontendsAddHTTPCmd())
	cmd.AddCommand(newFrontendsRemoveHTTPCmd())
	cmd.AddCommand(newFrontendsAddHTTPSCmd())
	cmd.AddCommand(newFrontendsRemoveHTTPSCmd())
	cmd.AddCommand(newFrontendsAddTCPCmd())
	cmd.AddCommand(newFrontendsRemoveTCPCmd())

	return cmd
}

// sozuctl frontends list
func newFrontendsListCmd() *cobra.Command {
	var (
		http  bool
		https bool
		tcp   bool
		host  string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List frontends (optionally filtered)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var filters *sozuinternal.FrontendFilters
			if http || https || tcp || host != "" {
				f := &sozuinternal.FrontendFilters{}
				if http {
					f.Http = proto.Bool(true)
				}
				if https {
					f.Https = proto.Bool(true)
				}
				if tcp {
					f.Tcp = proto.Bool(true)
				}
				if host != "" {
					f.Domain = &host
				}
				filters = f
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.ListFrontends(ctx, filters)
			if err != nil {
				return fmt.Errorf("ListFrontends: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().BoolVar(&http, "http", false, "include HTTP frontends")
	cmd.Flags().BoolVar(&https, "https", false, "include HTTPS frontends")
	cmd.Flags().BoolVar(&tcp, "tcp", false, "include TCP frontends")
	cmd.Flags().StringVar(&host, "hostname", "", "filter by hostname")

	return cmd
}

// sozuctl frontends add-http
func newFrontendsAddHTTPCmd() *cobra.Command {
	var (
		clusterID string
		addrStr   string
		hostname  string
		path      string
		pathKind  string
		method    string
		position  string
	)

	cmd := &cobra.Command{
		Use:   "add-http",
		Short: "Add an HTTP frontend",
		RunE: func(cmd *cobra.Command, args []string) error {
			if clusterID == "" {
				return fmt.Errorf("--cluster-id is required")
			}
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}
			if hostname == "" {
				return fmt.Errorf("--hostname is required")
			}

			addr, err := parseInternalSocketAddress(addrStr)
			if err != nil {
				return err
			}

			req := &sozuinternal.RequestHttpFrontend{
				ClusterId: &clusterID,
				Address:   addr,
				Hostname:  &hostname,
			}

			if position != "" {
				pos, err := parseRulePosition(position)
				if err != nil {
					return err
				}
				req.Position = &pos
			}
			if method != "" {
				req.Method = &method
			}

			// if path != "" {
			// 	kindStr := pathKind
			// 	if kindStr == "" {
			// 		kindStr = "prefix"
			// 	}
			// 	kind, err := parsePathRuleKind(kindStr)
			// 	if err != nil {
			// 		return err
			// 	}
			// 	rule := &sozuinternal.PathRule{
			// 		Path: &path,
			// 		Kind: &kind,
			// 	}
			// 	req.PathRules = []*sozuinternal.PathRule{rule}
			// }

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.AddHttpFrontend(ctx, req)
			if err != nil {
				return fmt.Errorf("AddHttpFrontend: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "cluster id")
	cmd.Flags().StringVar(&addrStr, "addr", "", "frontend bind address (ip:port)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname")
	cmd.Flags().StringVar(&path, "path", "", "path to match (optional)")
	cmd.Flags().StringVar(&pathKind, "path-kind", "prefix", "path rule kind: prefix|regex|equals")
	cmd.Flags().StringVar(&method, "method", "", "HTTP method to match (optional)")
	cmd.Flags().StringVar(&position, "position", "pre", "rule position: pre|post|tree")

	return cmd
}

// sozuctl frontends remove-http
func newFrontendsRemoveHTTPCmd() *cobra.Command {
	var (
		clusterID string
		addrStr   string
		hostname  string
		path      string
		method    string
		position  string
	)

	cmd := &cobra.Command{
		Use:   "remove-http",
		Short: "Remove an HTTP frontend",
		RunE: func(cmd *cobra.Command, args []string) error {
			if clusterID == "" {
				return fmt.Errorf("--cluster-id is required")
			}
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}
			if hostname == "" {
				return fmt.Errorf("--hostname is required")
			}

			addr, err := parseInternalSocketAddress(addrStr)
			if err != nil {
				return err
			}

			req := &sozuinternal.RequestHttpFrontend{
				ClusterId: &clusterID,
				Address:   addr,
				Hostname:  &hostname,
			}

			if position != "" {
				pos, err := parseRulePosition(position)
				if err != nil {
					return err
				}
				req.Position = &pos
			}
			if method != "" {
				req.Method = &method
			}
			// if path != "" {
			// 	req.PathRules = []*sozuinternal.PathRule{
			// 		{Path: &path},
			// 	}
			// }

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.RemoveHttpFrontend(ctx, req)
			if err != nil {
				return fmt.Errorf("RemoveHttpFrontend: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "cluster id")
	cmd.Flags().StringVar(&addrStr, "addr", "", "frontend bind address (ip:port)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname")
	cmd.Flags().StringVar(&path, "path", "", "path to match (optional)")
	cmd.Flags().StringVar(&method, "method", "", "HTTP method (optional)")
	cmd.Flags().StringVar(&position, "position", "pre", "rule position: pre|post|tree")

	return cmd
}

// sozuctl frontends add-https
func newFrontendsAddHTTPSCmd() *cobra.Command {
	var (
		clusterID string
		addrStr   string
		hostname  string
		path      string
		pathKind  string
		method    string
		position  string
	)

	cmd := &cobra.Command{
		Use:   "add-https",
		Short: "Add an HTTPS frontend",
		RunE: func(cmd *cobra.Command, args []string) error {
			if clusterID == "" {
				return fmt.Errorf("--cluster-id is required")
			}
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}
			if hostname == "" {
				return fmt.Errorf("--hostname is required")
			}

			addr, err := parseInternalSocketAddress(addrStr)
			if err != nil {
				return err
			}

			req := &sozuinternal.RequestHttpFrontend{
				ClusterId: &clusterID,
				Address:   addr,
				Hostname:  &hostname,
			}

			if position != "" {
				pos, err := parseRulePosition(position)
				if err != nil {
					return err
				}
				req.Position = &pos
			}
			if method != "" {
				req.Method = &method
			}
			// if path != "" {
			// 	kindStr := pathKind
			// 	if kindStr == "" {
			// 		kindStr = "prefix"
			// 	}
			// 	kind, err := parsePathRuleKind(kindStr)
			// 	if err != nil {
			// 		return err
			// 	}
			// 	rule := &sozuinternal.PathRule{
			// 		Path: &path,
			// 		Kind: &kind,
			// 	}
			// 	req.PathRules = []*sozuinternal.PathRule{rule}
			// }

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.AddHttpsFrontend(ctx, req)
			if err != nil {
				return fmt.Errorf("AddHttpsFrontend: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "cluster id")
	cmd.Flags().StringVar(&addrStr, "addr", "", "frontend bind address (ip:port)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname")
	cmd.Flags().StringVar(&path, "path", "", "path to match (optional)")
	cmd.Flags().StringVar(&pathKind, "path-kind", "prefix", "path rule kind: prefix|regex|equals")
	cmd.Flags().StringVar(&method, "method", "", "HTTP method to match (optional)")
	cmd.Flags().StringVar(&position, "position", "pre", "rule position: pre|post|tree")

	return cmd
}

// sozuctl frontends remove-https
func newFrontendsRemoveHTTPSCmd() *cobra.Command {
	var (
		clusterID string
		addrStr   string
		hostname  string
		path      string
		method    string
		position  string
	)

	cmd := &cobra.Command{
		Use:   "remove-https",
		Short: "Remove an HTTPS frontend",
		RunE: func(cmd *cobra.Command, args []string) error {
			if clusterID == "" {
				return fmt.Errorf("--cluster-id is required")
			}
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}
			if hostname == "" {
				return fmt.Errorf("--hostname is required")
			}

			addr, err := parseInternalSocketAddress(addrStr)
			if err != nil {
				return err
			}

			req := &sozuinternal.RequestHttpFrontend{
				ClusterId: &clusterID,
				Address:   addr,
				Hostname:  &hostname,
			}

			if position != "" {
				pos, err := parseRulePosition(position)
				if err != nil {
					return err
				}
				req.Position = &pos
			}
			if method != "" {
				req.Method = &method
			}
			// if path != "" {
			// 	req.PathRules = []*sozuinternal.PathRule{
			// 		{Path: &path},
			// 	}
			// }

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.RemoveHttpsFrontend(ctx, req)
			if err != nil {
				return fmt.Errorf("RemoveHttpsFrontend: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "cluster id")
	cmd.Flags().StringVar(&addrStr, "addr", "", "frontend bind address (ip:port)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname")
	cmd.Flags().StringVar(&path, "path", "", "path to match (optional)")
	cmd.Flags().StringVar(&method, "method", "", "HTTP method (optional)")
	cmd.Flags().StringVar(&position, "position", "pre", "rule position: pre|post|tree")

	return cmd
}

// sozuctl frontends add-tcp
func newFrontendsAddTCPCmd() *cobra.Command {
	var (
		clusterID string
		addrStr   string
		backendID string
	)

	cmd := &cobra.Command{
		Use:   "add-tcp",
		Short: "Add a TCP frontend",
		RunE: func(cmd *cobra.Command, args []string) error {
			if clusterID == "" {
				return fmt.Errorf("--cluster-id is required")
			}
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}
			if backendID == "" {
				return fmt.Errorf("--backend-id is required")
			}

			addr, err := parseInternalSocketAddress(addrStr)
			if err != nil {
				return err
			}

			req := &sozuinternal.RequestTcpFrontend{
				ClusterId: &clusterID,
				Address:   addr,
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.AddTcpFrontend(ctx, req)
			if err != nil {
				return fmt.Errorf("AddTcpFrontend: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "cluster id")
	cmd.Flags().StringVar(&addrStr, "addr", "", "frontend bind address (ip:port)")
	cmd.Flags().StringVar(&backendID, "backend-id", "", "backend id to route to")

	return cmd
}

// sozuctl frontends remove-tcp
func newFrontendsRemoveTCPCmd() *cobra.Command {
	var (
		clusterID string
		addrStr   string
		backendID string
	)

	cmd := &cobra.Command{
		Use:   "remove-tcp",
		Short: "Remove a TCP frontend",
		RunE: func(cmd *cobra.Command, args []string) error {
			if clusterID == "" {
				return fmt.Errorf("--cluster-id is required")
			}
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}
			if backendID == "" {
				return fmt.Errorf("--backend-id is required")
			}

			addr, err := parseInternalSocketAddress(addrStr)
			if err != nil {
				return err
			}

			req := &sozuinternal.RequestTcpFrontend{
				ClusterId: &clusterID,
				Address:   addr,
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.RemoveTcpFrontend(ctx, req)
			if err != nil {
				return fmt.Errorf("RemoveTcpFrontend: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "cluster id")
	cmd.Flags().StringVar(&addrStr, "addr", "", "frontend bind address (ip:port)")
	cmd.Flags().StringVar(&backendID, "backend-id", "", "backend id to route to")

	return cmd
}

// -----------------------------------------------------------------------------
// clusters group
// -----------------------------------------------------------------------------

func newClustersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clusters",
		Short: "Manage clusters",
	}

	cmd.AddCommand(newClustersAddCmd())
	cmd.AddCommand(newClustersRemoveCmd())

	return cmd
}

// sozuctl clusters add
func newClustersAddCmd() *cobra.Command {
	var (
		clusterID     string
		sticky        bool
		httpsRedirect bool
		proxyProto    string
		lbAlgo        string
		answer503     string
		loadMetricStr string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			if clusterID == "" {
				return fmt.Errorf("--cluster-id is required")
			}

			proxyCfg, err := parseProxyProtocolConfig(proxyProto)
			if err != nil {
				return err
			}
			lb, err := parseLoadBalancing(lbAlgo)
			if err != nil {
				return err
			}
			lm, err := parseLoadMetric(loadMetricStr)
			if err != nil {
				return err
			}

			cl := &sozuinternal.Cluster{
				ClusterId:     &clusterID,
				StickySession: &sticky,
				HttpsRedirect: &httpsRedirect,
				LoadBalancing: &lb,
				LoadMetric:    &lm,
			}
			if proxyProto != "" {
				cl.ProxyProtocol = &proxyCfg
			}
			if answer503 != "" {
				cl.Answer_503 = &answer503
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.AddCluster(ctx, cl)
			if err != nil {
				return fmt.Errorf("AddCluster: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "cluster id")
	cmd.Flags().BoolVar(&sticky, "sticky-session", false, "enable sticky sessions")
	cmd.Flags().BoolVar(&httpsRedirect, "https-redirect", false, "redirect HTTP to HTTPS")
	cmd.Flags().StringVar(&proxyProto, "proxy-protocol", "", "proxy protocol: expect_header|send_header|relay_header|none")
	cmd.Flags().StringVar(&lbAlgo, "lb-algorithm", "round_robin", "load balancing algorithm: round_robin|random|least_loaded|power_of_two")
	cmd.Flags().StringVar(&answer503, "answer-503", "", "custom 503 response text (optional)")
	cmd.Flags().StringVar(&loadMetricStr, "load-metric", "connections", "load metric: connections|requests|connection_time")

	return cmd
}

// sozuctl clusters remove
func newClustersRemoveCmd() *cobra.Command {
	var clusterID string

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a cluster by ID",
		RunE: func(cmd *cobra.Command, args []string) error {
			if clusterID == "" {
				return fmt.Errorf("--cluster-id is required")
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.RemoveCluster(ctx, clusterID)
			if err != nil {
				return fmt.Errorf("RemoveCluster: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "cluster id")

	return cmd
}

// -----------------------------------------------------------------------------
// backends group
// -----------------------------------------------------------------------------

func newBackendsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backends",
		Short: "Manage backends",
	}

	cmd.AddCommand(newBackendsAddCmd())
	cmd.AddCommand(newBackendsRemoveCmd())

	return cmd
}

// sozuctl backends add
func newBackendsAddCmd() *cobra.Command {
	var (
		clusterID string
		backendID string
		addrStr   string
		stickyID  string
		weight    int32
		backup    bool
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a backend",
		RunE: func(cmd *cobra.Command, args []string) error {
			if clusterID == "" {
				return fmt.Errorf("--cluster-id is required")
			}
			if backendID == "" {
				return fmt.Errorf("--backend-id is required")
			}
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}

			addr, err := parseInternalSocketAddress(addrStr)
			if err != nil {
				return err
			}

			req := &sozuinternal.AddBackend{
				ClusterId: &clusterID,
				BackendId: &backendID,
				Address:   addr,
				Backup:    &backup,
			}
			if stickyID != "" {
				req.StickyId = &stickyID
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.AddBackend(ctx, req)
			if err != nil {
				return fmt.Errorf("AddBackend: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "cluster id")
	cmd.Flags().StringVar(&backendID, "backend-id", "", "backend id")
	cmd.Flags().StringVar(&addrStr, "addr", "", "backend address (ip:port)")
	cmd.Flags().StringVar(&stickyID, "sticky-id", "", "sticky id for backend (optional)")
	cmd.Flags().Int32Var(&weight, "weight", 0, "backend weight (optional)")
	cmd.Flags().BoolVar(&backup, "backup", false, "mark backend as backup")

	return cmd
}

// sozuctl backends remove
func newBackendsRemoveCmd() *cobra.Command {
	var (
		clusterID string
		backendID string
		addrStr   string
	)

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a backend",
		RunE: func(cmd *cobra.Command, args []string) error {
			if clusterID == "" {
				return fmt.Errorf("--cluster-id is required")
			}
			if backendID == "" {
				return fmt.Errorf("--backend-id is required")
			}
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}

			addr, err := parseInternalSocketAddress(addrStr)
			if err != nil {
				return err
			}

			req := &sozuinternal.RemoveBackend{
				ClusterId: &clusterID,
				BackendId: &backendID,
				Address:   addr,
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.RemoveBackend(ctx, req)
			if err != nil {
				return fmt.Errorf("RemoveBackend: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "cluster id")
	cmd.Flags().StringVar(&backendID, "backend-id", "", "backend id")
	cmd.Flags().StringVar(&addrStr, "addr", "", "backend address (ip:port)")

	return cmd
}

// -----------------------------------------------------------------------------
// certificates group
// -----------------------------------------------------------------------------

func newCertificatesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificates",
		Short: "Manage TLS certificates",
	}

	cmd.AddCommand(newCertificatesAddCmd())
	cmd.AddCommand(newCertificatesReplaceCmd())
	cmd.AddCommand(newCertificatesRemoveCmd())

	return cmd
}

// sozuctl certificates add
func newCertificatesAddCmd() *cobra.Command {
	var (
		addrStr   string
		certFile  string
		keyFile   string
		names     []string
		versions  []string
		expiresAt int64
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}

			addr, err := parseInternalSocketAddress(addrStr)
			if err != nil {
				return err
			}

			ck, err := buildCertAndKey(certFile, keyFile, names, versions)
			if err != nil {
				return err
			}

			req := &sozuinternal.AddCertificate{
				Address:     addr,
				Certificate: ck,
			}
			if expiresAt != 0 {
				req.ExpiredAt = &expiresAt
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.AddCertificate(ctx, req)
			if err != nil {
				return fmt.Errorf("AddCertificate: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&addrStr, "addr", "", "TLS address (ip:port)")
	cmd.Flags().StringVar(&certFile, "cert-file", "", "PEM certificate file")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "PEM private key file")
	cmd.Flags().StringSliceVar(&names, "name", nil, "SNI name(s) this certificate is valid for (repeatable)")
	cmd.Flags().StringSliceVar(&versions, "tls-version", nil, "TLS versions (e.g. tls1.2,tls1.3)")
	cmd.Flags().Int64Var(&expiresAt, "expires-at", 0, "expiration timestamp (unix seconds, optional)")

	return cmd
}

// sozuctl certificates replace
func newCertificatesReplaceCmd() *cobra.Command {
	var (
		addrStr     string
		fingerprint string
		certFile    string
		keyFile     string
		names       []string
		versions    []string
	)

	cmd := &cobra.Command{
		Use:   "replace",
		Short: "Replace a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}
			if fingerprint == "" {
				return fmt.Errorf("--fingerprint is required")
			}

			addr, err := parseInternalSocketAddress(addrStr)
			if err != nil {
				return err
			}

			ck, err := buildCertAndKey(certFile, keyFile, names, versions)
			if err != nil {
				return err
			}

			req := &sozuinternal.ReplaceCertificate{
				Address:        addr,
				OldFingerprint: &fingerprint,
				NewCertificate: ck,
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.ReplaceCertificate(ctx, req)
			if err != nil {
				return fmt.Errorf("ReplaceCertificate: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&addrStr, "addr", "", "TLS address (ip:port)")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "existing certificate fingerprint to replace")
	cmd.Flags().StringVar(&certFile, "cert-file", "", "PEM certificate file")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "PEM private key file")
	cmd.Flags().StringSliceVar(&names, "name", nil, "SNI name(s) this certificate is valid for (repeatable)")
	cmd.Flags().StringSliceVar(&versions, "tls-version", nil, "TLS versions (e.g. tls1.2,tls1.3)")

	return cmd
}

// sozuctl certificates remove
func newCertificatesRemoveCmd() *cobra.Command {
	var (
		addrStr     string
		fingerprint string
	)

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if addrStr == "" {
				return fmt.Errorf("--addr is required (ip:port)")
			}
			if fingerprint == "" {
				return fmt.Errorf("--fingerprint is required")
			}

			addr, err := parseInternalSocketAddress(addrStr)
			if err != nil {
				return err
			}

			req := &sozuinternal.RemoveCertificate{
				Address:     addr,
				Fingerprint: &fingerprint,
			}

			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.RemoveCertificate(ctx, req)
			if err != nil {
				return fmt.Errorf("RemoveCertificate: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.Flags().StringVar(&addrStr, "addr", "", "TLS address (ip:port)")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "certificate fingerprint to remove")

	return cmd
}

// -----------------------------------------------------------------------------
// workers group
// -----------------------------------------------------------------------------

func newWorkersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workers",
		Short: "Inspect workers",
	}

	cmd.AddCommand(newWorkersListCmd())
	return cmd
}

// sozuctl workers list
func newWorkersListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List workers",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := newClient()
			ctx, cancel := contextWithTimeout()
			defer cancel()

			resp, err := cli.ListWorkers(ctx)
			if err != nil {
				return fmt.Errorf("ListWorkers: %w", err)
			}
			printResponse(resp)
			return nil
		},
	}
	return cmd
}
