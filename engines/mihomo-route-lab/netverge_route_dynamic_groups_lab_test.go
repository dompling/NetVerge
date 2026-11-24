// Test-only native policy group experiment. No product group implementation.
package tunnel_test

import (
	"context"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	G "github.com/metacubex/mihomo/adapter/outboundgroup"
	PD "github.com/metacubex/mihomo/adapter/provider"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

// Deterministic health snapshots only. DialContext and all selection
// algorithms remain real upstream implementations. No external probes.
type nvGroupMember struct {
	C.Proxy
	alive atomic.Bool
	delay atomic.Uint32
}

func (m *nvGroupMember) AliveForTestUrl(string) bool { return m.alive.Load() }
func (m *nvGroupMember) LastDelayForTestUrl(string) uint16 {
	if !m.alive.Load() { return 65535 }
	return uint16(m.delay.Load())
}
func nvGroupSet(m *nvGroupMember, alive bool, delay uint32) {
	m.alive.Store(alive)
	m.delay.Store(delay)
}

func nvGroupProvider(t *testing.T, name string, members ...C.Proxy) []P.ProxyProvider {
	t.Helper()
	hc := PD.NewHealthCheck(members, "", 0, 0, true, nil)
	p,err := PD.NewCompatibleProvider(name,members,hc)
	if err!=nil { t.Fatal(err) }
	t.Cleanup(func(){ _=p.Close() })
	return []P.ProxyProvider{p}
}

func TestNetVergeRouteLeaseDynamicGroups(t *testing.T) {
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	originA := nvWhistleNewOriginWithProof(t,"group-a-proof")
	originB := nvWhistleNewOriginWithProof(t,"group-b-proof")
	var countA,countB atomic.Int32
	a := &nvGroupMember{Proxy:nvLabProxy(t,"route-a",nvWhistleAuthority,originA.server.Listener.Addr().String(),&countA)}
	b := &nvGroupMember{Proxy:nvLabProxy(t,"route-b",nvWhistleAuthority,originB.server.Listener.Addr().String(),&countB)}
	nvGroupSet(a,true,10)
	nvGroupSet(b,true,100)
	reject := adapter.NewProxy(outbound.NewReject())
	rejectDrop := adapter.NewProxy(outbound.NewRejectDrop())
	pd := nvGroupProvider(t,"fixture-members",a,b)
	opt := func(name string) G.GroupCommonOption { return G.GroupCommonOption{Name:name,URL:"https://route.netverge.test/route-proof"} }
	selector,err := G.NewSelector(opt("select"),G.SelectorOption{DefaultSelected:a.Name()},reject,pd)
	if err!=nil { t.Fatal(err) }
	urltest,err := G.NewURLTest(opt("url-test"),G.URLTestOption{},reject,pd)
	if err!=nil { t.Fatal(err) }
	fallback,err := G.NewFallback(opt("fallback"),G.FallbackOption{},reject,pd)
	if err!=nil { t.Fatal(err) }
	balance,err := G.NewLoadBalance(opt("load-balance"),G.LoadBalanceOption{Strategy:"round-robin"},reject,pd)
	if err!=nil { t.Fatal(err) }
	inner,err := G.NewSelector(opt("inner-reject"),G.SelectorOption{DefaultSelected:reject.Name()},reject,nvGroupProvider(t,"reject-members",reject,rejectDrop))
	if err!=nil { t.Fatal(err) }
	innerProxy := adapter.NewProxy(inner)
	outer,err := G.NewSelector(opt("outer-reject"),G.SelectorOption{DefaultSelected:inner.Name()},reject,nvGroupProvider(t,"nested-members",innerProxy))
	if err!=nil { t.Fatal(err) }
	groups := map[string]C.Proxy{
		"select":adapter.NewProxy(selector),"url-test":adapter.NewProxy(urltest),
		"fallback":adapter.NewProxy(fallback),"load-balance":adapter.NewProxy(balance),
		"outer-reject":adapter.NewProxy(outer),
	}
	for _, spec := range []struct{ name, strategy, hashKey string }{
		{"hash", "consistent-hashing", ""},
		{"hash-user", "consistent-hashing", "in-user"},
		{"sticky", "sticky-sessions", ""},
		{"sticky-user", "sticky-sessions", "in-user"},
	} {
		lb, err := G.NewLoadBalance(opt(spec.name), G.LoadBalanceOption{Strategy: spec.strategy, HashKey: spec.hashKey}, reject, pd)
		if err != nil { t.Fatal(err) }
		groups[spec.name] = adapter.NewProxy(lb)
	}
	proxies := map[string]C.Proxy{a.Name():a,b.Name():b,reject.Name():reject,rejectDrop.Name():rejectDrop,inner.Name():innerProxy}
	var rules []C.Rule
	for _,name := range []string{"select","url-test","fallback","load-balance","outer-reject","hash","hash-user","sticky","sticky-user"} {
		proxies[name]=groups[name]
		r,err := R.NewProcess(name,name,C.ProcessName)
		if err!=nil { t.Fatal(err) }
		rules=append(rules,r)
	}
	tunnel.UpdateProxies(proxies,nil)
	tunnel.UpdateRules(rules,nil,nil)

	// Resolve once and invoke the returned group. Never preselect the leaf
	// or redial after the user changes the group or health changes.
	dial := func(name string) C.Conn {
		metadata := &C.Metadata{Type:C.TUN,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443,Process:name,SrcIP:netip.MustParseAddr("192.0.2.25"),InUser:"fixture-user"}
		p,_,err := tunnel.NetVergeLabResolveMetadata(metadata)
		if err!=nil || p!=groups[name] { t.Fatalf("%s original group decision failed: %v",name,err) }
		ctx,cancel := context.WithTimeout(context.Background(),nvLabTimeout)
		defer cancel()
		c,err := p.DialContext(ctx,metadata.Clone())
		if err!=nil { t.Fatalf("%s original dial failed: %v",name,err) }
		return c
	}
	type fixture struct { name,key string; lease *nvLabLease; origin *nvWhistleOrigin; proof string }
	var fixtures []fixture
	routes := make(map[string]*nvLabLease)
	prepare := func(group string, want *nvGroupMember) *nvGroupMember {
		t.Helper()
		beforeA,beforeB := countA.Load(),countB.Load()
		conn := dial(group)
		t.Cleanup(func(){_=conn.Close()})
		// For hashing, observe the first actual dial rather than unwrapping
		// or predicting a native algorithm's selected leaf.
		if want == nil {
			chain := conn.Chains()
			if len(chain) != 2 { t.Fatalf("%s invalid original chain: %v", group, chain) }
			switch chain[0] {
			case a.Name(): want = a
			case b.Name(): want = b
			default: t.Fatalf("%s unexpected member: %v", group, chain)
			}
		}
		// This test knows the exact fixture adapter instances and expected
		// topology. It does not authorize unknown production chain names.
		if N.NeedHandshake(conn) || !slices.Equal([]string(conn.Chains()),[]string{want.Name(),group}) {
			t.Fatalf("%s original dial chain %v, expected [%s %s]",group,conn.Chains(),want.Name(),group)
		}
		f := fixture{name:group+"/"+want.Name(),key:nvWhistlePassword(t)}
		if want==a {
			if countA.Load()!=beforeA+1 || countB.Load()!=beforeB { t.Fatal("wrong actual proxy A dial") }
			f.origin,f.proof=originA,"group-a-proof"
		} else {
			if countB.Load()!=beforeB+1 || countA.Load()!=beforeA { t.Fatal("wrong actual proxy B dial") }
			f.origin,f.proof=originB,"group-b-proof"
		}
		if !nvLabTypedEligible(groups[group],conn) {
			t.Fatalf("%s actual eager group stream not admitted by adapter type",group)
		}
		f.lease=nvLabLeaseVerifiedStream(t,conn,nvWhistleAuthority)
		routes[f.key]=f.lease
		fixtures=append(fixtures,f)
		return want
	}
	prepare("select",a)
	if err=selector.Set(b.Name()); err!=nil { t.Fatal(err) }
	prepare("select",b)

	prepare("url-test",a)
	nvGroupSet(a,true,100)
	nvGroupSet(b,true,10)
	// Use the native reset path after a simulated health snapshot change.
	urltest.ForceSet("")
	prepare("url-test",b)

	prepare("fallback",a)
	nvGroupSet(a,false,100)
	prepare("fallback",b)
	nvGroupSet(a,true,10)
	nvGroupSet(b,true,100)

	prepare("load-balance",a)
	prepare("load-balance",b)
	if countA.Load()!=4 || countB.Load()!=4 { t.Fatal("unexpected group dial count") }

	// Preserve native hashing and session affinity without reproducing
	// the hash algorithm. Only consistent hashing has deterministic
	// healthy-member fallback; sticky retry is intentionally not forced.
	for _, group := range []string{"hash","hash-user","sticky","sticky-user"} {
		first := prepare(group,nil)
		prepare(group,first)
		if group == "hash" || group == "hash-user" {
			other := a
			if first == a { other = b }
			nvGroupSet(first,false,100)
			prepare(group,other)
			nvGroupSet(a,true,10)
			nvGroupSet(b,true,100)
		}
	}
	wantA,wantB := int32(0),int32(0)
	for _, f := range fixtures {
		if f.origin == originA { wantA++ } else { wantB++ }
	}
	if countA.Load()!=wantA || countB.Load()!=wantB || wantA+wantB!=18 {
		t.Fatal("unexpected native group dial totals")
	}

	// Both rejected nested routes can return nil dial errors. A successful
	// group dial is insufficient to authorize MITM. No listener is created.
	for _,denied := range []C.Proxy{reject,rejectDrop} {
		if err=inner.Set(denied.Name()); err!=nil { t.Fatal(err) }
		c := dial("outer-reject")
		if !slices.Equal([]string(c.Chains()),[]string{denied.Name(),inner.Name(),outer.Name()}) {
			c.Close()
			t.Fatal("nested reject chain changed")
		}
		trace, ok := c.(nvLabTypeTrace)
		if !ok || !slices.Equal(trace.NetVergeLabAdapterTypes(), []C.AdapterType{denied.Type(),C.Selector,C.Selector}) {
			c.Close()
			t.Fatal("nested rejection type evidence missing")
		}
		if nvLabTypedEligible(groups["outer-reject"],c) { c.Close(); t.Fatal("rejected group admitted") }
		c.Close()
	}
	if countA.Load()!=wantA || countB.Load()!=wantB { t.Fatal("reject reached real outbound") }

	// All eighteen leases were established before the shared worker starts.
	// A subsequent selection change must not change an existing stream.
	if err=selector.Set(a.Name()); err!=nil { t.Fatal(err) }
	roots := filepath.Join(t.TempDir(),"group-roots.pem")
	caA,err := os.ReadFile(originA.caPath)
	if err!=nil { t.Fatal(err) }
	caB,err := os.ReadFile(originB.caPath)
	if err!=nil { t.Fatal(err) }
	if err=os.WriteFile(roots,append(caA,caB...),0600); err!=nil { t.Fatal(err) }
	w := nvWhistleLaunch(t,roots,routes,nil)
	for _,f := range fixtures {
		t.Run(f.name,func(t *testing.T){
			before := f.origin.requests.Load()
			auth := "Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+f.key))
			c,status,err := nvWhistleConnect(w,nvWhistleAuthority,auth)
			if err!=nil || status!=200 { t.Fatalf("group ingress: %d %v",status,err) }
			peer,err := nvWhistleRequestProof(c,w.root,f.proof)
			if err!=nil || string(peer)==string(f.origin.leaf) { t.Fatalf("group HTTPS proof failed: %v",err) }
			if !f.lease.used.Load() || f.origin.requests.Load()!=before+1 {
				t.Fatal("original connection not consumed exactly once")
			}
			if countA.Load()!=wantA || countB.Load()!=wantB { t.Fatal("Whistle redialed group") }
		})
	}
	if originA.requests.Load()!=wantA || originB.requests.Load()!=wantB || originA.leaked.Load() || originB.leaked.Load() {
		t.Fatal("cross-route response or internal credential leak")
	}
	t.Log("PASS: native select, URL-Test, fallback, round-robin, consistent hashing and sticky session group dials preserved in one Whistle process; nested rejects excluded")
}
