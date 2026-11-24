// Test-only integration with the real, unmodified NetVerge Whistle worker.
// One isolated process per lease is an experiment, not a production design.
package tunnel_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

const nvWhistleHost = "route.netverge.test"
const nvWhistleAuthority = nvWhistleHost + ":443"

type nvWhistleOrigin struct {
	server *httptest.Server
	caPath string
	root *x509.CertPool
	leaf []byte
	requests atomic.Int32
	leaked atomic.Bool
}

func nvWhistleNewOrigin(t *testing.T) *nvWhistleOrigin {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "NetVerge route lab origin CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil { t.Fatal(err) }
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: nvWhistleHost}, DNSNames: []string{nvWhistleHost}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil { t.Fatal(err) }
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	root := x509.NewCertPool()
	if !root.AppendCertsFromPEM(caPEM) { t.Fatal("invalid origin CA") }
	caPath := filepath.Join(t.TempDir(), "origin-ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil { t.Fatal(err) }
	origin := &nvWhistleOrigin{caPath: caPath, root: root, leaf: leafDER}
	origin.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Whistle-Tunnel-Data") != "" {
			origin.leaked.Store(true)
		}
		if r.Method != http.MethodGet || r.URL.Path != "/route-proof" ||
			(r.Host != nvWhistleAuthority && r.Host != nvWhistleHost) {
			w.WriteHeader(400)
			return
		}
		origin.requests.Add(1)
		_, _ = io.WriteString(w, "original-route")
	}))
	origin.server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}}
	origin.server.StartTLS()
	t.Cleanup(origin.server.Close)
	return origin
}

func nvWhistlePassword(t *testing.T) string {
	t.Helper()
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil { t.Fatal(err) }
	return base64.RawURLEncoding.EncodeToString(b[:])
}

type nvWhistleWorker struct {
	port int
	auth string
	root *x509.CertPool
	cmd *exec.Cmd
	done chan struct{}
}

func nvWhistleStart(t *testing.T, lease *nvLabLease, caPath string) *nvWhistleWorker {
	t.Helper()
	worker := os.Getenv("NETVERGE_ROUTE_LAB_WORKER")
	if !filepath.IsAbs(worker) { t.Fatal("NETVERGE_ROUTE_LAB_WORKER must point to the actual worker") }
	if _, err := os.Stat(worker); err != nil { t.Fatal(err) }
	// Existing worker requires an explicit nonzero port. The test binds and
	// releases a temporary local port; authenticated readiness is mandatory.
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	dir := t.TempDir()
	password := nvWhistlePassword(t)
	settings, err := json.Marshal(map[string]any{
		"dataDir": dir, "port": port, "returnPort": lease.listener.Addr().(*net.TCPAddr).Port,
		"hosts": []string{nvWhistleHost}, "password": lease.password, "forwardPassword": password,
		"targetPort": 443, "healthSecret": nvWhistlePassword(t),
	})
	if err != nil { t.Fatal(err) }
	cmd := exec.Command("node", worker)
	env := make([]string, 0, len(os.Environ()) + 4)
	for _, entry := range os.Environ() {
		key := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		if strings.HasPrefix(key, "WHISTLE_") || strings.HasPrefix(key, "PFORK_") ||
			strings.HasPrefix(key, "NETVERGE_MITM_") || strings.HasPrefix(key, "NETVERGE_LAB_") {
			continue
		}
		switch key {
		case "HOME", "USERPROFILE", "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		env = append(env, entry)
	}
	cmd.Env = append(env, "HOME="+dir, "USERPROFILE="+dir, "NODE_EXTRA_CA_CERTS="+caPath, "NETVERGE_MITM_WORKER_CONFIG="+string(settings))
	stdin, err := cmd.StdinPipe()
	if err != nil { t.Fatal(err) }
	stdout, err := cmd.StdoutPipe()
	if err != nil { t.Fatal(err) }
	// Avoid logging worker credentials, keys or arbitrary child stdout.
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil { t.Fatal(err) }
	w := &nvWhistleWorker{port:port, auth:"Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+password)), cmd:cmd, done:make(chan struct{})}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = w.cmd.Process.Kill()
		select {
		case <-w.done:
		case <-time.After(5*time.Second):
			t.Error("Whistle child did not exit")
		}
	})
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		published := false
		for scanner.Scan() {
			if !published && strings.HasPrefix(scanner.Text(), "NETVERGE_MITM_READY ") {
				published = true
				ready <- strings.TrimPrefix(scanner.Text(), "NETVERGE_MITM_READY ")
			}
		}
		_ = cmd.Wait()
		close(w.done)
	}()
	select {
	case encoded := <-ready:
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil { t.Fatal("invalid worker CA encoding") }
		ca, err := x509.ParseCertificate(der)
		if err != nil || !ca.IsCA || ca.CheckSignatureFrom(ca) != nil { t.Fatal("invalid worker root CA") }
		w.root = x509.NewCertPool()
		w.root.AddCert(ca)
	case <-w.done:
		t.Fatal("Whistle exited before readiness")
	case <-time.After(25*time.Second):
		t.Fatal("Whistle readiness timeout")
	}
	return w
}

func nvWhistleConnect(w *nvWhistleWorker, authority, auth string) (net.Conn, int, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", w.port), nvLabTimeout)
	if err != nil { return nil, 0, err }
	_ = c.SetDeadline(time.Now().Add(nvLabTimeout))
	if _, err = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", authority, authority, auth); err != nil {
		c.Close()
		return nil, 0, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil { c.Close(); return nil, 0, err }
	if resp.StatusCode != 200 { c.Close(); return nil, resp.StatusCode, nil }
	return nvLabBufferedConn{Conn:c,reader:br}, 200, nil
}

func nvWhistleRequest(c net.Conn, root *x509.CertPool) ([]byte, error) {
	client := tls.Client(c, &tls.Config{RootCAs:root, ServerName:nvWhistleHost, NextProtos:[]string{"http/1.1"}})
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(nvLabTimeout))
	if err := client.Handshake(); err != nil { return nil, err }
	peer := client.ConnectionState().PeerCertificates[0].Raw
	if _, err := io.WriteString(client, "GET /route-proof HTTP/1.1\r\nHost: "+nvWhistleAuthority+"\r\nConnection: close\r\n\r\n"); err != nil { return nil, err }
	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method:http.MethodGet})
	if err != nil { return nil, err }
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil || resp.StatusCode != 200 || string(body) != "original-route" { return nil, fmt.Errorf("unexpected origin response: status=%d err=%v", resp.StatusCode, err) }
	return peer,nil
}

func TestNetVergeRouteLeaseWhistle(t *testing.T) {
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	origin := nvWhistleNewOrigin(t)
	var countA, countB atomic.Int32
	a := nvLabProxy(t, "route-a", nvWhistleAuthority, origin.server.Listener.Addr().String(), &countA)
	b := nvLabProxy(t, "route-b", nvWhistleAuthority, origin.server.Listener.Addr().String(), &countB)
	reject := adapter.NewProxy(outbound.NewReject())
	tunnel.UpdateProxies(map[string]C.Proxy{"route-a":a,"route-b":b,"REJECT":reject},nil)
	processRule, err := R.NewProcess("original-app-b", "route-b", C.ProcessName)
	if err != nil { t.Fatal(err) }
	blockRule, err := R.NewProcess("blocked-app", "REJECT", C.ProcessName)
	if err != nil { t.Fatal(err) }
	tunnel.UpdateRules([]C.Rule{blockRule, processRule, R.NewDomain(nvWhistleHost,"route-a")},nil,nil)

	dialOriginal := func(processName string, expected C.Proxy) C.Conn {
		metadata := &C.Metadata{Type:C.TUN,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443,Process:processName}
		proxy, _, err := tunnel.NetVergeLabResolveMetadata(metadata)
		if err != nil || proxy != expected { t.Fatalf("original route selection failed: %v",err) }
		ctx,cancel := context.WithTimeout(context.Background(),nvLabTimeout)
		defer cancel()
		c,err := proxy.DialContext(ctx,metadata.Clone())
		if err != nil { t.Fatal(err) }
		return c
	}
	// Baseline: actual original TLS peer and actual original adapter.
	for _, f := range []struct{process string; proxy C.Proxy}{{"original-app-a",a},{"original-app-b",b}} {
		c := dialOriginal(f.process,f.proxy)
		peer,err := nvWhistleRequest(c,origin.root)
		if err != nil || string(peer)!=string(origin.leaf) { t.Fatalf("baseline TLS failed: %v",err) }
	}
	if countA.Load()!=1 || countB.Load()!=1 || origin.requests.Load()!=2 { t.Fatal("baseline route counts differ") }

	// Same authority, two original decisions. Each has an independent
	// already-open connection and worker; no global egress rule is installed.
	leaseA := nvLabNewLease(t,a,dialOriginal("original-app-a",a),nvWhistleAuthority)
	workerA := nvWhistleStart(t,leaseA,origin.caPath)
	leaseB := nvLabNewLease(t,b,dialOriginal("original-app-b",b),nvWhistleAuthority)
	workerB := nvWhistleStart(t,leaseB,origin.caPath)
	if countA.Load()!=2 || countB.Load()!=2 { t.Fatal("unexpected initial dials") }
	if c,status,err := nvWhistleConnect(workerA,nvWhistleAuthority,workerB.auth); c!=nil || status!=407 || err!=nil {
		if c!=nil { c.Close() }
		t.Fatalf("cross-worker credential admitted: status=%d err=%v",status,err)
	}
	if c,status,err := nvWhistleConnect(workerA,"wrong.netverge.test:443",workerA.auth); c!=nil || status!=403 || err!=nil {
		if c!=nil { c.Close() }
		t.Fatalf("cross-authority admission: status=%d err=%v",status,err)
	}
	for _, f := range []struct{name string; w *nvWhistleWorker; lease *nvLabLease; other *nvLabLease}{{"route-a",workerA,leaseA,leaseB},{"route-b",workerB,leaseB,leaseA}} {
		before := origin.requests.Load()
		c,status,err := nvWhistleConnect(f.w,nvWhistleAuthority,f.w.auth)
		if err!=nil || status!=200 { t.Fatalf("%s ingress: status=%d err=%v",f.name,status,err) }
		peer,err := nvWhistleRequest(c,f.w.root)
		if err!=nil || string(peer)==string(origin.leaf) { t.Fatalf("%s MITM TLS proof failed: %v",f.name,err) }
		if !f.lease.used.Load() || origin.requests.Load()!=before+1 { t.Fatalf("%s did not use the original lease",f.name) }
		if f.name=="route-a" && f.other.used.Load() { t.Fatal("route B lease consumed by route A") }
		if countA.Load()!=2 || countB.Load()!=2 { t.Fatal("unexpected second outbound dial") }
		t.Logf("PASS: %s used the original adapter's one-shot stream with a different trusted TLS leaf",f.name)
	}
	if origin.leaked.Load() { t.Fatal("internal credentials reached the origin") }

	// Consumed or revoked lease must not cause any further origin request.
	before := origin.requests.Load()
	c,status,err := nvWhistleConnect(workerA,nvWhistleAuthority,workerA.auth)
	if err==nil && status==200 {
		if _,err := nvWhistleRequest(c,workerA.root); err==nil { t.Fatal("consumed lease permitted a second origin request") }
	}
	if origin.requests.Load()!=before { t.Fatal("consumed lease fell back to origin") }

	revoked := nvLabNewLease(t,a,dialOriginal("original-app-a",a),nvWhistleAuthority)
	revokedWorker := nvWhistleStart(t,revoked,origin.caPath)
	revoked.close()
	c,status,err = nvWhistleConnect(revokedWorker,nvWhistleAuthority,revokedWorker.auth)
	if err==nil && status==200 {
		if _,err := nvWhistleRequest(c,revokedWorker.root); err==nil { t.Fatal("revoked lease permitted origin request") }
	}
	if origin.requests.Load()!=before || revoked.used.Load() { t.Fatal("revoked route fell back or was consumed") }
	blocked := dialOriginal("blocked-app",reject)
	defer blocked.Close()
	if nvLabEligible(reject,blocked) || origin.requests.Load()!=before || countA.Load()!=3 || countB.Load()!=2 { t.Fatal("REJECT route admitted or dialed") }
}
