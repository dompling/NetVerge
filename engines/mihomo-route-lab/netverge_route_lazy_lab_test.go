// Controlled first-write fixture: real native group and HTTP outbound,
// simulated protocol handshake. Not evidence of SS/VMess/Trojan support.
package tunnel_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	G "github.com/metacubex/mihomo/adapter/outboundgroup"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

// Inject a deterministic first-write gate without changing the original
// native dial or its type trace. The relay uses io.Copy, hence Write.
type nvLazyFixtureConn struct {
	C.Conn
	fail bool
	started atomic.Int32
	done atomic.Bool
}

func (c *nvLazyFixtureConn) NeedHandshake() bool { return !c.done.Load() }
func (c *nvLazyFixtureConn) Upstream() any { return c.Conn }
func (c *nvLazyFixtureConn) Write(p []byte) (int,error) {
	if c.done.Load() { return c.Conn.Write(p) }
	c.started.Add(1)
	if len(p)==0 || p[0]!=0x16 || c.fail {
		return 0,errors.New("controlled lazy first-write failure")
	}
	n,err := c.Conn.Write(p)
	if err==nil && n==len(p) { c.done.Store(true) }
	return n,err
}

type nvLazyFixtureProxy struct {
	C.Proxy
	fail atomic.Bool
}
func (p *nvLazyFixtureProxy) DialContext(ctx context.Context,m *C.Metadata) (C.Conn,error) {
	c,err := p.Proxy.DialContext(ctx,m)
	if err!=nil { return nil,err }
	return &nvLazyFixtureConn{Conn:c,fail:p.fail.Load()},nil
}

// Explicitly scoped to this fixture. The previous eager-only admission
// remains unchanged. Look through native first-write callback wrappers
// without unwrapping the actual stream used for relay.
func nvLabLazyFixture(c C.Conn,group C.Proxy) (*nvLazyFixtureConn,bool) {
	if c==nil || group==nil || !N.NeedHandshake(c) { return nil,false }
	f,ok := N.FindUpstream[*nvLazyFixtureConn](c,nil)
	if !ok { return nil,false }
	trace,ok := N.FindUpstream[nvLabTypeTrace](c,nil)
	if !ok || !slices.Equal(trace.NetVergeLabAdapterTypes(),[]C.AdapterType{C.Http,C.Selector}) ||
		group.Type()!=C.Selector || len(c.Chains())!=2 {
		return nil,false
	}
	return f,true
}

func TestNetVergeRouteLeaseLazyFirstWrite(t *testing.T) {
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	aOrigin := nvWhistleNewOriginWithProof(t,"lazy-a-proof")
	bOrigin := nvWhistleNewOriginWithProof(t,"lazy-b-proof")
	var countA,countB atomic.Int32
	a := &nvLazyFixtureProxy{Proxy:nvLabProxy(t,"lazy-a",nvWhistleAuthority,aOrigin.server.Listener.Addr().String(),&countA)}
	b := &nvLazyFixtureProxy{Proxy:nvLabProxy(t,"lazy-b",nvWhistleAuthority,bOrigin.server.Listener.Addr().String(),&countB)}
	reject := adapter.NewProxy(outbound.NewReject())
	sel,err := G.NewSelector(G.GroupCommonOption{Name:"lazy-group",URL:"https://route.netverge.test/route-proof"},G.SelectorOption{DefaultSelected:a.Name()},reject,nvGroupProvider(t,"lazy-members",a,b))
	if err!=nil { t.Fatal(err) }
	group := adapter.NewProxy(sel)
	tunnel.UpdateProxies(map[string]C.Proxy{group.Name():group,a.Name():a,b.Name():b,reject.Name():reject},nil)
	tunnel.UpdateRules([]C.Rule{R.NewDomain(nvWhistleHost,group.Name())},nil,nil)

	dial := func(want C.Proxy) (*nvLabLease,*nvLazyFixtureConn) {
		t.Helper()
		m := &C.Metadata{Type:C.TUN,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443}
		p,_,err := tunnel.NetVergeLabResolveMetadata(m)
		if err!=nil || p!=group { t.Fatalf("original decision: %v",err) }
		ctx,cancel := context.WithTimeout(context.Background(),nvLabTimeout)
		defer cancel()
		c,err := p.DialContext(ctx,m.Clone())
		if err!=nil { t.Fatal(err) }
		t.Cleanup(func(){_=c.Close()})
		f,ok := nvLabLazyFixture(c,group)
		if !ok || nvLabTypedEligible(group,c) || !slices.Equal([]string(c.Chains()),[]string{want.Name(),group.Name()}) {
			t.Fatal("lazy original stream evidence missing or eager gate admitted lazy stream")
		}
		if f.started.Load()!=0 || f.done.Load() { t.Fatal("handshake already triggered") }
		return nvLabLeaseVerifiedStream(t,c,nvWhistleAuthority),f
	}

	la,fa := dial(a)
	if err=sel.Set(b.Name()); err!=nil { t.Fatal(err) }
	lb,fb := dial(b)
	if err=sel.Set(a.Name()); err!=nil { t.Fatal(err) }
	a.fail.Store(true)
	lf,ff := dial(a)
	a.fail.Store(false)
	if err=sel.Set(b.Name()); err!=nil { t.Fatal(err) }
	if countA.Load()!=2 || countB.Load()!=1 { t.Fatal("original dial counts differ") }

	// Failure path: the original connection is closed without any fallback.
	c := nvLabConnect(t,lf,nvWhistleAuthority,lf.token,200)
	tc := tls.Client(c,&tls.Config{RootCAs:aOrigin.root,ServerName:nvWhistleHost})
	if err=tc.Handshake(); err==nil { tc.Close(); t.Fatal("failed first write unexpectedly succeeded") }
	tc.Close()
	if ff.started.Load()!=1 || ff.done.Load() || !lf.used.Load() || aOrigin.requests.Load()!=0 ||
		countA.Load()!=2 || countB.Load()!=1 {
		t.Fatal("failed first write retried, redirected or reached origin")
	}
	nvLabConnect(t,lf,nvWhistleAuthority,lf.token,403)

	// Success path: real shared Whistle initiates TLS on the two original
	// streams after the group selection changed. No second dial is allowed.
	roots := filepath.Join(t.TempDir(),"lazy-roots.pem")
	caA,err := os.ReadFile(aOrigin.caPath)
	if err!=nil { t.Fatal(err) }
	caB,err := os.ReadFile(bOrigin.caPath)
	if err!=nil { t.Fatal(err) }
	if err=os.WriteFile(roots,append(caA,caB...),0600); err!=nil { t.Fatal(err) }
	keyA,keyB := nvWhistlePassword(t),nvWhistlePassword(t)
	w := nvWhistleLaunch(t,roots,map[string]*nvLabLease{keyA:la,keyB:lb},nil)
	if fa.started.Load()!=0 || fb.started.Load()!=0 { t.Fatal("worker readiness consumed an original stream") }
	for _,f := range []struct{
		key,proof string
		lease *nvLabLease
		lazy *nvLazyFixtureConn
		origin *nvWhistleOrigin
	}{
		{keyA,"lazy-a-proof",la,fa,aOrigin},
		{keyB,"lazy-b-proof",lb,fb,bOrigin},
	} {
		auth := "Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+f.key))
		c,status,err := nvWhistleConnect(w,nvWhistleAuthority,auth)
		if err!=nil || status!=200 { t.Fatalf("lazy ingress: %d %v",status,err) }
		peer,err := nvWhistleRequestProof(c,w.root,f.proof)
		if err!=nil || string(peer)==string(f.origin.leaf) { t.Fatalf("lazy TLS proof: %v",err) }
		if f.lazy.started.Load()!=1 || !f.lazy.done.Load() || !f.lease.used.Load() ||
			f.origin.requests.Load()!=1 { t.Fatal("first write did not complete exactly once") }
	}
	if countA.Load()!=2 || countB.Load()!=1 || aOrigin.leaked.Load() || bOrigin.leaked.Load() {
		t.Fatal("lazy handoff redialed or leaked credentials")
	}
	t.Log("PASS: controlled lazy first-write success and failure on original native group connections")
}
