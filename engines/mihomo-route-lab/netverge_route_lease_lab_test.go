// Copied into the pinned upstream tunnel package ONLY by the laboratory CI.
// This is not linked into a distributed Mihomo or NetVerge binary.
package tunnel_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	R "github.com/metacubex/mihomo/rules/common"
)

const nvLabTimeout = 10 * time.Second

// A deliberately narrow first experiment: lease only an already established,
// eager single-adapter connection. Never redial by an adapter name, accept
// metadata from the sidecar, or rematch on its loopback source. Groups and
// lazy handshakes need their own investigation before admission.
func nvLabEligible(proxy C.Proxy, conn C.Conn) bool {
	if proxy == nil || conn == nil {
		return false
	}
	switch proxy.Type() {
	case C.Direct, C.Http:
	default:
		return false
	}
	chain := conn.Chains()
	return len(chain) == 1 && chain[0] == proxy.Name() && !N.NeedHandshake(conn)
}

type nvLabLease struct {
	server *http.Server
	listener net.Listener
	upstream C.Conn
	token string
	password string
	used atomic.Bool
	mu sync.Mutex
	client net.Conn
	closed bool
	done chan struct{}
}

// The one-shot credential authorizes a single fixed authority and stream.
// The caller must own the original successful dial and close the lease when
// the original connection ends. This lab has no production control endpoint.
func nvLabNewLease(t *testing.T, proxy C.Proxy, upstream C.Conn, authority string) *nvLabLease {
	t.Helper()
	if !nvLabEligible(proxy, upstream) {
		t.Fatal("route is outside the eager single-adapter lab scope")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var secret [24]byte
	if _, err = rand.Read(secret[:]); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	password := base64.RawURLEncoding.EncodeToString(secret[:])
	lease := &nvLabLease{
		listener: listener, upstream: upstream, password: password,
		token: "Basic " + base64.StdEncoding.EncodeToString([]byte("netverge:" + password)),
		done: make(chan struct{}),
	}
	lease.server = &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		MaxHeaderBytes: 4096,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Values("Proxy-Authorization")
			if len(auth) != 1 || subtle.ConstantTimeCompare([]byte(auth[0]), []byte(lease.token)) != 1 {
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			if r.Method != http.MethodConnect || r.RequestURI != authority ||
				r.Host != authority || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			lease.mu.Lock()
			if lease.closed || !lease.used.CompareAndSwap(false, true) {
				lease.mu.Unlock()
				w.WriteHeader(http.StatusForbidden)
				return
			}
			client, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				lease.mu.Unlock()
				upstream.Close()
				return
			}
			lease.client = client
			lease.mu.Unlock()
			defer client.Close()
			defer upstream.Close()
			client.SetDeadline(time.Now().Add(nvLabTimeout))
			upstream.SetDeadline(time.Now().Add(nvLabTimeout))
			if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				return
			}
			if err = rw.Flush(); err != nil {
				return
			}
			nvLabRelay(client, rw.Reader, upstream)
		}),
	}
	go func() {
		defer close(lease.done)
		_ = lease.server.Serve(listener)
	}()
	t.Cleanup(lease.close)
	return lease
}

func (l *nvLabLease) close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	if l.client != nil {
		l.client.Close()
	}
	l.upstream.Close()
	l.mu.Unlock()
	l.server.Close()
	<-l.done
}

func nvLabRelay(client net.Conn, input io.Reader, upstream net.Conn) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(upstream, input)
		upstream.Close()
		client.Close()
	}()
	_, _ = io.Copy(client, upstream)
	client.Close()
	upstream.Close()
	<-done
}

// Two independent controlled HTTP proxy fixtures identify which real adapter
// received the dial. Neither accepts a caller-selected destination; all data
// remains on localhost. A fresh CONNECT is counted before any TLS bytes.
func nvLabProxy(t *testing.T, name, authority, destination string, count *atomic.Int32) C.Proxy {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.RequestURI != authority {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		upstream, err := net.DialTimeout("tcp", destination, nvLabTimeout)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		client, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		count.Add(1)
		// Allow the already-dialed origin stream to wait while isolated workers start.
		client.SetDeadline(time.Now().Add(75 * time.Second))
		upstream.SetDeadline(time.Now().Add(75 * time.Second))
		_, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err == nil {
			err = rw.Flush()
		}
		if err == nil {
			nvLabRelay(client, rw.Reader, upstream)
		}
	}))
	t.Cleanup(srv.Close)
	host, portText, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	httpAdapter, err := outbound.NewHttp(outbound.HttpOption{Name: name, Server: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	p := adapter.NewProxy(httpAdapter)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

type nvLabBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c nvLabBufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func nvLabConnect(t *testing.T, lease *nvLabLease, authority, token string, want int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", lease.listener.Addr().String(), nvLabTimeout)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(nvLabTimeout))
	if _, err = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", authority, authority, token); err != nil {
		c.Close()
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		c.Close()
		t.Fatalf("CONNECT status %d, want %d", resp.StatusCode, want)
	}
	if want != 200 {
		c.Close()
		return nil
	}
	return nvLabBufferedConn{Conn: c, reader: br}
}

func nvLabTLSRequest(t *testing.T, conn net.Conn, config *tls.Config) {
	t.Helper()
	client := tls.Client(conn, config.Clone())
	defer client.Close()
	client.SetDeadline(time.Now().Add(nvLabTimeout))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "GET /route-proof HTTP/1.1\r\nHost: route.netverge.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 || string(body) != "original-route" {
		t.Fatalf("origin proof failed: status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
}

func TestNetVergeRouteLeaseOriginalDecision(t *testing.T) {
	// These are real upstream resolver/rule/adapter calls. OS process lookup
	// is disabled only in this fixture; the original process fields are seeded
	// as test metadata. Actual TUN and OS process identification remain open.
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/route-proof" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, "original-route")
	}))
	t.Cleanup(origin.Close)
	tlsConfig := origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.ServerName = "127.0.0.1"
	tlsConfig.InsecureSkipVerify = false
	originAddr := origin.Listener.Addr().(*net.TCPAddr)
	authority := "route.netverge.test:443"
	var countA, countB atomic.Int32
	a := nvLabProxy(t, "route-a", authority, originAddr.String(), &countA)
	b := nvLabProxy(t, "route-b", authority, originAddr.String(), &countB)
	direct := adapter.NewProxy(outbound.NewDirect())
	reject := adapter.NewProxy(outbound.NewReject())
	rejectDrop := adapter.NewProxy(outbound.NewRejectDrop())
	t.Cleanup(func() { _ = direct.Close() })
	tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": direct, "REJECT": reject, "REJECT-DROP": rejectDrop, "route-a": a, "route-b": b}, nil)
	processRule, err := R.NewProcess("fixture-process", "route-b", C.ProcessName)
	if err != nil { t.Fatal(err) }
	ipRule, err := R.NewIPCIDR("192.0.2.0/24", "route-b", R.WithIPCIDRNoResolve(true))
	if err != nil { t.Fatal(err) }
	sourceRule, err := R.NewIPCIDR("198.51.100.0/24", "route-b", R.WithIPCIDRSourceIP(true))
	if err != nil { t.Fatal(err) }
	tunnel.UpdateRules([]C.Rule{
		R.NewDomain("blocked.netverge.test", "REJECT"),
		R.NewDomain("drop.netverge.test", "REJECT-DROP"),
		processRule, ipRule, sourceRule,
		R.NewDomain("route.netverge.test", "route-a"),
	}, nil, nil)

	fixtures := []struct {
		name string
		metadata C.Metadata
		want C.Proxy
		counter *atomic.Int32
		ruleType C.RuleType
	}{
		{"domain", C.Metadata{Type: C.TUN, NetWork: C.TCP, Host: "route.netverge.test", DstPort: 443}, a, &countA, C.Domain},
		{"process priority", C.Metadata{Type: C.TUN, NetWork: C.TCP, Host: "route.netverge.test", DstPort: 443, Process: "fixture-process", ProcessPath: "/fixture/original"}, b, &countB, C.ProcessName},
		{"destination IP priority", C.Metadata{Type: C.TUN, NetWork: C.TCP, Host: "route.netverge.test", DstPort: 443, DstIP: netip.MustParseAddr("192.0.2.5")}, b, &countB, C.IPCIDR},
		{"source IP priority", C.Metadata{Type: C.TUN, NetWork: C.TCP, Host: "route.netverge.test", DstPort: 443, SrcIP: netip.MustParseAddr("198.51.100.5")}, b, &countB, C.SrcIPCIDR},
		{"direct", C.Metadata{Type: C.TUN, NetWork: C.TCP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(originAddr.Port)}, direct, nil, 0},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			metadata := f.metadata.Clone()
			proxy, rule, err := tunnel.NetVergeLabResolveMetadata(metadata)
			if err != nil || proxy != f.want {
				t.Fatalf("original decision changed: proxy=%v rule=%v err=%v", proxy, rule, err)
			}
			if f.counter != nil && (rule == nil || rule.RuleType() != f.ruleType) {
				t.Fatalf("unexpected original rule %v", rule)
			}
			beforeA, beforeB := countA.Load(), countB.Load()
			ctx, cancel := context.WithTimeout(context.Background(), nvLabTimeout)
			defer cancel()
			baseline, err := proxy.DialContext(ctx, metadata.Clone())
			if err != nil { t.Fatal(err) }
			defer baseline.Close()
			nvLabTLSRequest(t, baseline, tlsConfig)

			// Lease the exact connection produced by the original proxy object.
			// No second resolveMetadata, proxy-name lookup, or caller metadata.
			upstream, err := proxy.DialContext(ctx, metadata.Clone())
			if err != nil { t.Fatal(err) }
			defer upstream.Close()
			lease := nvLabNewLease(t, proxy, upstream, metadata.RemoteAddress())
			nvLabConnect(t, lease, metadata.RemoteAddress(), "Basic invalid", 407)
			nvLabConnect(t, lease, "other.netverge.test:443", lease.token, 403)
			c := nvLabConnect(t, lease, metadata.RemoteAddress(), lease.token, 200)
			nvLabTLSRequest(t, c, tlsConfig)
			nvLabConnect(t, lease, metadata.RemoteAddress(), lease.token, 403)
			if f.counter == &countA {
				if countA.Load()-beforeA != 2 || countB.Load()!=beforeB { t.Fatal("route A did not exclusively carry both connections") }
			} else if f.counter == &countB {
				if countB.Load()-beforeB != 2 || countA.Load()!=beforeA { t.Fatal("route B did not exclusively carry both connections") }
			} else if countA.Load()!=beforeA || countB.Load()!=beforeB {
				t.Fatal("direct request unexpectedly used proxy")
			}
		})
	}
	for _, host := range []string{"blocked.netverge.test", "drop.netverge.test"} {
		t.Run(host, func(t *testing.T) {
			beforeA, beforeB := countA.Load(), countB.Load()
			metadata := &C.Metadata{Type:C.TUN, NetWork:C.TCP, Host:host, DstPort:443, Process:"fixture-process"}
			proxy, _, err := tunnel.NetVergeLabResolveMetadata(metadata)
			if err != nil || (proxy != reject && proxy != rejectDrop) {
				t.Fatalf("reject precedence lost: %v", err)
			}
			conn, err := proxy.DialContext(context.Background(), metadata)
			if err != nil { t.Fatal(err) }
			defer conn.Close()
			if nvLabEligible(proxy, conn) { t.Fatal("rejected route admitted to lease") }
			if countA.Load()!=beforeA || countB.Load()!=beforeB { t.Fatal("reject unexpectedly dialed a real endpoint") }
		})
	}
}
