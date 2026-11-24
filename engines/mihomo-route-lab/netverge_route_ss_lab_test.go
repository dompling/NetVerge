// Test-only real Shadowsocks AEAD transport; no production admission changes.
package tunnel_test

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	G "github.com/metacubex/mihomo/adapter/outboundgroup"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/tunnel"
)

type nvSSFixture struct {
	proxy C.Proxy
	accepted atomic.Int32
	decoded atomic.Int32
	bad atomic.Int32
}

// Use the actual upstream Shadowsocks server cipher and destination parser.
// Never resolve a caller-supplied address; this fixture is localhost-only.
func nvNewSSFixture(t *testing.T,name,cipher string,origin *nvWhistleOrigin) *nvSSFixture {
	t.Helper()
	password := nvWhistlePassword(t)
	serverCipher,err := core.PickCipher(cipher,nil,password)
	if err!=nil { t.Fatal(err) }
	l,err := net.Listen("tcp4","127.0.0.1:0")
	if err!=nil { t.Fatal(err) }
	f := &nvSSFixture{}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c,err := l.Accept()
			if err!=nil { return }
			f.accepted.Add(1)
			wg.Add(1)
			go func(raw net.Conn) {
				defer wg.Done()
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(75*time.Second))
				stream := serverCipher.StreamConn(raw)
				target,err := socks5.ReadAddr0(stream)
				if err!=nil || target.String()!=nvWhistleAuthority {
					f.bad.Add(1)
					return
				}
				f.decoded.Add(1)
				up,err := net.DialTimeout("tcp",origin.server.Listener.Addr().String(),nvLabTimeout)
				if err!=nil { f.bad.Add(1); return }
				defer up.Close()
				_ = up.SetDeadline(time.Now().Add(75*time.Second))
				nvLabRelay(stream,stream,up)
			}(c)
		}
	}()
	t.Cleanup(func(){ _=l.Close(); <-done; wg.Wait() })
	host,portString,err := net.SplitHostPort(l.Addr().String())
	if err!=nil { t.Fatal(err) }
	port,err := strconv.Atoi(portString)
	if err!=nil { t.Fatal(err) }
	ss,err := outbound.NewShadowSocks(outbound.ShadowSocksOption{Name:name,Server:host,Port:port,Cipher:cipher,Password:password})
	if err!=nil { t.Fatal(err) }
	f.proxy=adapter.NewProxy(ss)
	t.Cleanup(func(){_=f.proxy.Close()})
	return f
}

func TestNetVergeRouteLeaseShadowsocks(t *testing.T) {
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	oa := nvWhistleNewOriginWithProof(t,"ss-aes-proof")
	ob := nvWhistleNewOriginWithProof(t,"ss-chacha-proof")
	a := nvNewSSFixture(t,"ss-aes","aes-128-gcm",oa)
	b := nvNewSSFixture(t,"ss-chacha","chacha20-ietf-poly1305",ob)
	reject := adapter.NewProxy(outbound.NewReject())
	sel,err := G.NewSelector(G.GroupCommonOption{Name:"ss-group",URL:"https://route.netverge.test/route-proof"},G.SelectorOption{DefaultSelected:a.proxy.Name()},reject,nvGroupProvider(t,"ss-members",a.proxy,b.proxy))
	if err!=nil { t.Fatal(err) }
	group := adapter.NewProxy(sel)
	tunnel.UpdateProxies(map[string]C.Proxy{group.Name():group,a.proxy.Name():a.proxy,b.proxy.Name():b.proxy,reject.Name():reject},nil)
	tunnel.UpdateRules([]C.Rule{R.NewDomain(nvWhistleHost,group.Name())},nil,nil)
	dial := func(want C.Proxy) *nvLabLease {
		t.Helper()
		m := &C.Metadata{Type:C.TUN,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443}
		p,_,err := tunnel.NetVergeLabResolveMetadata(m)
		if err!=nil || p!=group { t.Fatalf("original SS group decision: %v",err) }
		ctx,cancel := context.WithTimeout(context.Background(),nvLabTimeout)
		defer cancel()
		c,err := p.DialContext(ctx,m.Clone())
		if err!=nil { t.Fatal(err) }
		t.Cleanup(func(){_=c.Close()})
		trace,ok := N.FindUpstream[nvLabTypeTrace](c,nil)
		if !ok || !slices.Equal(trace.NetVergeLabAdapterTypes(),[]C.AdapterType{C.Shadowsocks,C.Selector}) ||
			!slices.Equal([]string(c.Chains()),[]string{want.Name(),group.Name()}) {
			t.Fatal("actual Shadowsocks dial evidence missing")
		}
		if nvLabTypedEligible(group,c) { t.Fatal("experimental Shadowsocks admitted to eager-only gate") }
		t.Logf("native Shadowsocks %s NeedHandshake=%t",want.Name(),N.NeedHandshake(c))
		// Plain AEAD may be eager. Do not claim lazy support from this result.
		return nvLabLeaseVerifiedStream(t,c,nvWhistleAuthority)
	}
	la:=dial(a.proxy)
	if err=sel.Set(b.proxy.Name()); err!=nil { t.Fatal(err) }
	lb:=dial(b.proxy)
	if err=sel.Set(a.proxy.Name()); err!=nil { t.Fatal(err) }
	roots:=filepath.Join(t.TempDir(),"ss-roots.pem")
	caA,err:=os.ReadFile(oa.caPath)
	if err!=nil { t.Fatal(err) }
	caB,err:=os.ReadFile(ob.caPath)
	if err!=nil { t.Fatal(err) }
	if err=os.WriteFile(roots,append(caA,caB...),0600); err!=nil { t.Fatal(err) }
	ka,kb:=nvWhistlePassword(t),nvWhistlePassword(t)
	w:=nvWhistleLaunch(t,roots,map[string]*nvLabLease{ka:la,kb:lb},nil)
	for _,f:=range []struct{
		key,proof string
		lease *nvLabLease
		origin *nvWhistleOrigin
	}{{ka,"ss-aes-proof",la,oa},{kb,"ss-chacha-proof",lb,ob}} {
		auth:="Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+f.key))
		c,status,err:=nvWhistleConnect(w,nvWhistleAuthority,auth)
		if err!=nil || status!=200 { t.Fatalf("SS ingress: %d %v",status,err) }
		peer,err:=nvWhistleRequestProof(c,w.root,f.proof)
		if err!=nil || string(peer)==string(f.origin.leaf) { t.Fatalf("SS TLS proof: %v",err) }
		if !f.lease.used.Load() || f.origin.requests.Load()!=1 { t.Fatal("original SS stream not consumed exactly once") }
		_,status,err=nvWhistleConnect(w,nvWhistleAuthority,auth)
		if err!=nil || status!=403 { t.Fatalf("SS lease replay: %d %v",status,err) }
	}
	for _,f:=range []*nvSSFixture{a,b} {
		if f.accepted.Load()!=1 || f.decoded.Load()!=1 || f.bad.Load()!=0 {
			t.Fatalf("SS connection or encrypted destination proof failed: accepted=%d decoded=%d bad=%d",f.accepted.Load(),f.decoded.Load(),f.bad.Load())
		}
	}
	if oa.leaked.Load() || ob.leaked.Load() { t.Fatal("credential leak") }
	t.Log("PASS: real AES-GCM and ChaCha20-Poly1305 Shadowsocks streams preserved through one Whistle worker")
}
