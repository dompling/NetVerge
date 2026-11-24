// Test-only shared Whistle experiment; all sockets and trust roots are local.
package tunnel_test

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"strings"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

func TestNetVergeRouteLeaseSharedWhistle(t *testing.T) {
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)

	// Different physical TLS origins for the same authority: a swapped
	// upstream connection or incorrectly reused agent changes the body.
	originA := nvWhistleNewOriginWithProof(t, "route-a-proof")
	originB := nvWhistleNewOriginWithProof(t, "route-b-proof")
	var countA, countB atomic.Int32
	a := nvLabProxy(t, "route-a", nvWhistleAuthority, originA.server.Listener.Addr().String(), &countA)
	b := nvLabProxy(t, "route-b", nvWhistleAuthority, originB.server.Listener.Addr().String(), &countB)
	tunnel.UpdateProxies(map[string]C.Proxy{"route-a":a,"route-b":b},nil)
	rule, err := R.NewProcess("original-b", "route-b", C.ProcessName)
	if err != nil { t.Fatal(err) }
	tunnel.UpdateRules([]C.Rule{rule,R.NewDomain(nvWhistleHost,"route-a")},nil,nil)
	newLease := func(name string, want C.Proxy) *nvLabLease {
		metadata := &C.Metadata{Type:C.TUN,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443,Process:name}
		p,_,err := tunnel.NetVergeLabResolveMetadata(metadata)
		if err!=nil || p!=want { t.Fatalf("original decision failed: %v",err) }
		ctx,cancel := context.WithTimeout(context.Background(),nvLabTimeout)
		defer cancel()
		c,err := p.DialContext(ctx,metadata.Clone())
		if err!=nil { t.Fatal(err) }
		return nvLabNewLease(t,p,c,nvWhistleAuthority)
	}
	// Two successful rounds test both sequential and overlapping requests
	// against one shared process, plus a revoked third route.
	leaseA1 := newLease("original-a",a)
	leaseB1 := newLease("original-b",b)
	leaseA2 := newLease("original-a",a)
	leaseB2 := newLease("original-b",b)
	revoked := newLease("original-a",a)
	keys := []string{nvWhistlePassword(t),nvWhistlePassword(t),nvWhistlePassword(t),nvWhistlePassword(t),nvWhistlePassword(t)}
	leases := []*nvLabLease{leaseA1,leaseB1,leaseA2,leaseB2,revoked}
	routes := make(map[string]*nvLabLease)
	for i,key := range keys { routes[key]=leases[i] }
	roots := filepath.Join(t.TempDir(),"origin-roots.pem")
	caA,err := os.ReadFile(originA.caPath)
	if err!=nil { t.Fatal(err) }
	caB,err := os.ReadFile(originB.caPath)
	if err!=nil { t.Fatal(err) }
	if err=os.WriteFile(roots,append(caA,caB...),0600); err!=nil { t.Fatal(err) }
	// Verify the exact combined roots with the same Node TLS implementation
	// before involving Whistle. Both connections are direct local fixture
	// handshakes, not application traffic or extra proxy dials.
	const nodeVerify = "const tls=require('node:tls'),fs=require('node:fs');const s=tls.connect({host:'127.0.0.1',port:Number(process.argv[2]),servername:'route.netverge.test',ca:fs.readFileSync(process.argv[1]),rejectUnauthorized:true},()=>{if(!s.authorized){process.exitCode=1;}s.end();});s.setTimeout(5000,()=>{s.destroy();process.exitCode=1;});s.on('error',e=>{console.error(e.code||'TLS_ERROR');process.exitCode=1;});"
	for _, origin := range []*nvWhistleOrigin{originA, originB} {
		ctx,cancel := context.WithTimeout(context.Background(),nvLabTimeout)
		_, port, err := net.SplitHostPort(origin.server.Listener.Addr().String())
		if err != nil { cancel(); t.Fatal(err) }
		cmd := exec.CommandContext(ctx,"node","-e",nodeVerify,roots,port)
		cmd.Env = append(os.Environ(),"NODE_OPTIONS=","NODE_TLS_REJECT_UNAUTHORIZED=1")
		out,err := cmd.CombinedOutput()
		cancel()
		if err!=nil {
			// Child emits only a fixed TLS error code.
			t.Fatalf("combined origin CA preflight failed: %s (%v)",strings.TrimSpace(string(out)),err)
		}
	}
	t.Log("PASS: both origin certificates verified by Node with combined roots")
	worker := nvWhistleLaunch(t,roots,routes,nil)
	authenticate := func(key string) string { return "Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+key)) }

	if c,status,err := nvWhistleConnect(worker,nvWhistleAuthority,"Basic invalid"); c!=nil || status!=407 || err!=nil {
		if c!=nil { c.Close() }
		t.Fatalf("unauthorized ingress: status=%d err=%v",status,err)
	}
	if c,status,err := nvWhistleConnect(worker,"wrong.netverge.test:443",authenticate(keys[0])); c!=nil || status!=403 || err!=nil {
		if c!=nil { c.Close() }
		t.Fatalf("wrong authority: status=%d err=%v",status,err)
	}
	request := func(i int, proof string, original []byte) error {
		c,status,err := nvWhistleConnect(worker,nvWhistleAuthority,authenticate(keys[i]))
		if err!=nil { return err }
		if c==nil || status!=200 { return &net.OpError{Op:"CONNECT",Net:"tcp",Err:C.ErrNotSupport} }
		peer,err := nvWhistleRequestProof(c,worker.root,proof)
		if err!=nil { return err }
		if string(peer)==string(original) || !leases[i].used.Load() { return C.ErrNotSupport }
		return nil
	}
	if err=request(0,"route-a-proof",originA.leaf); err!=nil { t.Fatal(err) }
	if originA.requests.Load()!=1 || originB.requests.Load()!=0 || leaseB1.used.Load() { t.Fatal("route A crossed into B") }
	if err=request(1,"route-b-proof",originB.leaf); err!=nil { t.Fatal(err) }
	if originA.requests.Load()!=1 || originB.requests.Load()!=1 { t.Fatal("route B crossed into A") }

	start := make(chan struct{})
	results := make(chan error,2)
	var wg sync.WaitGroup
	for i := 2; i<4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if i==2 { results<-request(i,"route-a-proof",originA.leaf) } else { results<-request(i,"route-b-proof",originB.leaf) }
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	for err:=range results { if err!=nil { t.Fatal(err) } }
	if originA.requests.Load()!=2 || originB.requests.Load()!=2 || countA.Load()!=3 || countB.Load()!=2 {
		t.Fatal("unexpected additional or crossed outbound connection")
	}

	if c,status,err := nvWhistleConnect(worker,nvWhistleAuthority,authenticate(keys[0])); c!=nil || status!=403 || err!=nil {
		if c!=nil { c.Close() }
		t.Fatalf("ingress replay: status=%d err=%v",status,err)
	}
	revoked.close()
	c,status,err := nvWhistleConnect(worker,nvWhistleAuthority,authenticate(keys[4]))
	if err==nil && status==200 {
		if _,err=nvWhistleRequestProof(c,worker.root,"route-a-proof"); err==nil { t.Fatal("revoked lease returned origin response") }
	}
	if revoked.used.Load() || originA.requests.Load()!=2 || originB.requests.Load()!=2 ||
		originA.leaked.Load() || originB.leaked.Load() || countA.Load()!=3 || countB.Load()!=2 {
		t.Fatal("revocation, credential isolation or route identity failed")
	}
	t.Log("PASS: one Whistle process, same hostname, distinct original routes, overlapping requests, no cross-route response or fallback")
}
