// Controlled real Trojan TCP+TLS transport. Local fixtures only.
package tunnel_test

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
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
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/trojan"
	"github.com/metacubex/mihomo/tunnel"
)

type nvTrojanFixture struct {
	proxy C.Proxy
	accepted atomic.Int32
	authenticated atomic.Int32
	bad atomic.Int32
	tlsRejected atomic.Int32
	option outbound.TrojanOption
}

func nvNewTrojanFixture(t *testing.T,name string,origin,certificate *nvWhistleOrigin) *nvTrojanFixture {
	t.Helper()
	password := nvWhistlePassword(t)
	key := trojan.Key(password)
	cert := certificate.server.TLS.Certificates[0]
	// Pin the independent proxy root, not the destination certificate.
	// Mihomo verifies both the pinned issuer and the TLS hostname.
	if len(cert.Certificate)!=2 { t.Fatal("missing proxy root") }
	if _,err:=x509.ParseCertificate(cert.Certificate[1]); err!=nil { t.Fatal(err) }
	config:= &tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS12,NextProtos:[]string{"http/1.1"}}
	l,err:=net.Listen("tcp4","127.0.0.1:0")
	if err!=nil { t.Fatal(err) }
	f:=&nvTrojanFixture{}
	var wg sync.WaitGroup
	done:=make(chan struct{})
	go func(){
		defer close(done)
		for {
			raw,err:=l.Accept()
			if err!=nil { return }
			f.accepted.Add(1)
			wg.Add(1)
			go func(raw net.Conn){
				defer wg.Done()
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(75*time.Second))
				stream:=tls.Server(raw,config)
				if err:=stream.Handshake(); err!=nil { f.tlsRejected.Add(1); return }
				// Mirror the upstream TCP header layout with its own key
				// and destination parser. Only the fixed fixture is allowed.
				var received [trojan.KeyLength]byte
				var crlf [2]byte
				if _,err:=io.ReadFull(stream,received[:]); err!=nil || subtle.ConstantTimeCompare(received[:],key[:])!=1 {
					f.bad.Add(1); return
				}
				if _,err:=io.ReadFull(stream,crlf[:]); err!=nil || string(crlf[:])!="\r\n" { f.bad.Add(1); return }
				command,err:=socks5.ReadByte(stream)
				if err!=nil || command!=trojan.CommandTCP { f.bad.Add(1); return }
				target,err:=socks5.ReadAddr0(stream)
				if err!=nil || target.String()!=nvWhistleAuthority { f.bad.Add(1); return }
				if _,err:=io.ReadFull(stream,crlf[:]); err!=nil || string(crlf[:])!="\r\n" { f.bad.Add(1); return }
				f.authenticated.Add(1)
				up,err:=net.DialTimeout("tcp",origin.server.Listener.Addr().String(),nvLabTimeout)
				if err!=nil { f.bad.Add(1); return }
				defer up.Close()
				_ = up.SetDeadline(time.Now().Add(75*time.Second))
				nvLabRelay(stream,stream,up)
			}(raw)
		}
	}()
	t.Cleanup(func(){_=l.Close(); <-done; wg.Wait()})
	host,portString,err:=net.SplitHostPort(l.Addr().String())
	if err!=nil { t.Fatal(err) }
	port,err:=strconv.Atoi(portString)
	if err!=nil { t.Fatal(err) }
	f.option=outbound.TrojanOption{Name:name,Server:host,Port:port,Password:password,SNI:nvWhistleHost,
		ALPN:[]string{"http/1.1"},Fingerprint:ca.CalculateFingerprint(cert.Certificate[1])}
	client,err:=outbound.NewTrojan(f.option)
	if err!=nil { t.Fatal(err) }
	f.proxy=adapter.NewProxy(client)
	t.Cleanup(func(){_=f.proxy.Close()})
	return f
}

func TestNetVergeRouteLeaseTrojan(t *testing.T) {
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	oa:=nvWhistleNewOriginWithProof(t,"trojan-origin-a")
	ob:=nvWhistleNewOriginWithProof(t,"trojan-origin-b")
	caA:=nvWhistleNewOriginWithProof(t,"trojan-proxy-a")
	caB:=nvWhistleNewOriginWithProof(t,"trojan-proxy-b")
	a:=nvNewTrojanFixture(t,"trojan-a",oa,caA)
	b:=nvNewTrojanFixture(t,"trojan-b",ob,caB)
	reject:=adapter.NewProxy(outbound.NewReject())
	sel,err:=G.NewSelector(G.GroupCommonOption{Name:"trojan-group",URL:"https://route.netverge.test/route-proof"},G.SelectorOption{DefaultSelected:a.proxy.Name()},reject,nvGroupProvider(t,"trojan-members",a.proxy,b.proxy))
	if err!=nil { t.Fatal(err) }
	group:=adapter.NewProxy(sel)
	tunnel.UpdateProxies(map[string]C.Proxy{group.Name():group,a.proxy.Name():a.proxy,b.proxy.Name():b.proxy,reject.Name():reject},nil)
	tunnel.UpdateRules([]C.Rule{R.NewDomain(nvWhistleHost,group.Name())},nil,nil)

	dial:=func(want C.Proxy)*nvLabLease{
		t.Helper()
		m:=&C.Metadata{Type:C.TUN,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443}
		p,_,err:=tunnel.NetVergeLabResolveMetadata(m)
		if err!=nil || p!=group { t.Fatalf("original Trojan group decision: %v",err) }
		ctx,cancel:=context.WithTimeout(context.Background(),nvLabTimeout)
		defer cancel()
		c,err:=p.DialContext(ctx,m.Clone())
		if err!=nil { t.Fatal(err) }
		t.Cleanup(func(){_=c.Close()})
		trace,ok:=N.FindUpstream[nvLabTypeTrace](c,nil)
		if !ok || !slices.Equal(trace.NetVergeLabAdapterTypes(),[]C.AdapterType{C.Trojan,C.Selector}) ||
			!slices.Equal([]string(c.Chains()),[]string{want.Name(),group.Name()}) {
			t.Fatal("actual Trojan dial evidence missing")
		}
		if nvLabTypedEligible(group,c) { t.Fatal("experimental Trojan admitted to eager-only gate") }
		t.Logf("native Trojan %s NeedHandshake=%t",want.Name(),N.NeedHandshake(c))
		return nvLabLeaseVerifiedStream(t,c,nvWhistleAuthority)
	}
	la:=dial(a.proxy)
	if err=sel.Set(b.proxy.Name()); err!=nil { t.Fatal(err) }
	lb:=dial(b.proxy)
	if err=sel.Set(a.proxy.Name()); err!=nil { t.Fatal(err) }
	roots:=filepath.Join(t.TempDir(),"trojan-origin-roots.pem")
	pemA,err:=os.ReadFile(oa.caPath)
	if err!=nil { t.Fatal(err) }
	pemB,err:=os.ReadFile(ob.caPath)
	if err!=nil { t.Fatal(err) }
	if err=os.WriteFile(roots,append(pemA,pemB...),0600); err!=nil { t.Fatal(err) }
	ka,kb:=nvWhistlePassword(t),nvWhistlePassword(t)
	w:=nvWhistleLaunch(t,roots,map[string]*nvLabLease{ka:la,kb:lb},nil)
	for _,f:=range []struct{
		key,proof string
		lease *nvLabLease
		origin *nvWhistleOrigin
	}{{ka,"trojan-origin-a",la,oa},{kb,"trojan-origin-b",lb,ob}}{
		auth:="Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+f.key))
		c,status,err:=nvWhistleConnect(w,nvWhistleAuthority,auth)
		if err!=nil || status!=200 { t.Fatalf("Trojan ingress: %d %v",status,err) }
		peer,err:=nvWhistleRequestProof(c,w.root,f.proof)
		if err!=nil || string(peer)==string(f.origin.leaf) { t.Fatalf("Trojan TLS proof: %v",err) }
		if !f.lease.Used() || f.origin.requests.Load()!=1 { t.Fatal("Trojan original stream not consumed once") }
		_,status,err=nvWhistleConnect(w,nvWhistleAuthority,auth)
		if err!=nil || status!=403 { t.Fatalf("Trojan lease replay: %d %v",status,err) }
	}
	for _,f:=range []*nvTrojanFixture{a,b}{
		if f.accepted.Load()!=1 || f.authenticated.Load()!=1 || f.bad.Load()!=0 || f.tlsRejected.Load()!=0 {
			t.Fatalf("Trojan proof counts: accepted=%d authenticated=%d bad=%d rejected=%d",f.accepted.Load(),f.authenticated.Load(),f.bad.Load(),f.tlsRejected.Load())
		}
	}
	// Wrong independent CA pin: native dial must fail before handing off
	// a stream. No additional target connection is permitted.
	badOption:=a.option
	badOption.Name="trojan-wrong-pin"
	badOption.Fingerprint=b.option.Fingerprint
	badClient,err:=outbound.NewTrojan(badOption)
	if err!=nil { t.Fatal(err) }
	defer badClient.Close()
	ctx,cancel:=context.WithTimeout(context.Background(),nvLabTimeout)
	defer cancel()
	c,err:=badClient.DialContext(ctx,&C.Metadata{Type:C.TUN,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443})
	if err==nil { if c!=nil {c.Close()}; t.Fatal("wrong TLS pin admitted") }
	if a.authenticated.Load()!=1 || b.authenticated.Load()!=1 || oa.requests.Load()!=1 || ob.requests.Load()!=1 ||
		oa.leaked.Load() || ob.leaked.Load() {
		t.Fatal("TLS failure reached origin or leaked credentials")
	}
	t.Log("PASS: real Trojan TCP+TLS original streams preserved; incorrect proxy CA pin denied")
}
