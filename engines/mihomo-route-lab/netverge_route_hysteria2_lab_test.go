// Real upstream Hysteria2 QUIC client and service with deferred stream request.
package tunnel_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	G "github.com/metacubex/mihomo/adapter/outboundgroup"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/log"
	hy2 "github.com/metacubex/sing-quic/hysteria2"
	"github.com/metacubex/tls"
	"github.com/metacubex/sing/common/auth"
	M "github.com/metacubex/sing/common/metadata"
	SN "github.com/metacubex/sing/common/network"
)

type nvHysteria2Fixture struct {
	proxy C.Proxy
	sourcesMu sync.Mutex
	sources map[string]struct{}
	decoded atomic.Int32
	bad atomic.Int32
	origin *nvWhistleOrigin
	user string
}

func (f *nvHysteria2Fixture) NewConnection(ctx context.Context,stream net.Conn,m M.Metadata) error {
	defer stream.Close()
	user,ok:=auth.UserFromContext[string](ctx)
	if !ok || user!=f.user || m.Destination.String()!=nvWhistleAuthority {
		f.bad.Add(1)
		return errors.New("unexpected Hysteria2 user or destination")
	}
	up,err:=net.DialTimeout("tcp",f.origin.server.Listener.Addr().String(),nvLabTimeout)
	if err!=nil { f.bad.Add(1); return err }
	defer up.Close()
	_ = up.SetDeadline(time.Now().Add(75*time.Second))
	f.sourcesMu.Lock()
	f.sources[m.Source.String()]=struct{}{}
	f.sourcesMu.Unlock()
	f.decoded.Add(1)
	nvLabRelay(stream,stream,up)
	return nil
}
func (f *nvHysteria2Fixture) NewPacketConnection(ctx context.Context,c SN.PacketConn,m M.Metadata) error {
	defer c.Close()
	f.bad.Add(1)
	return errors.New("unexpected Hysteria2 UDP")
}
func (f *nvHysteria2Fixture) NewError(ctx context.Context,err error) {
	f.bad.Add(1)
}
func nvNewHysteria2Fixture(t *testing.T,name string,origin,certificate *nvWhistleOrigin)*nvHysteria2Fixture {
	t.Helper()
	password:=nvWhistlePassword(t)
	f:=&nvHysteria2Fixture{origin:origin,user:name,sources:make(map[string]struct{})}
	cert:=certificate.server.TLS.Certificates[0]
	if len(cert.Certificate)!=2 { t.Fatal("missing independent proxy CA") }
	tlsConfig:=&tls.Config{
		Certificates:[]tls.Certificate{{Certificate:cert.Certificate,PrivateKey:cert.PrivateKey}},
		MinVersion:tls.VersionTLS13,NextProtos:[]string{"h3"},
	}
	ctx,cancel:=context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service,err:=hy2.NewService[string](hy2.ServiceOptions{
		Context:ctx,Logger:log.SingLogger,TLSConfig:tlsConfig,
		Handler:f,IgnoreClientBandwidth:true,UDPDisabled:true,UdpMTU:1197,
		UDPTimeout:time.Second*30,
	})
	if err!=nil { t.Fatal(err) }
	service.UpdateUsers([]string{name},[]string{password})
	socket,err:=net.ListenPacket("udp4","127.0.0.1:0")
	if err!=nil { t.Fatal(err) }
	t.Cleanup(func(){cancel();_=service.Close();_=socket.Close()})
	if err=service.Start(socket); err!=nil { t.Fatal(err) }
	port:=socket.LocalAddr().(*net.UDPAddr).Port
	client,err:=outbound.NewHysteria2(outbound.Hysteria2Option{
		Name:name,Server:"127.0.0.1",Port:port,Password:password,SNI:nvWhistleHost,
		ALPN:[]string{"h3"},Fingerprint:ca.CalculateFingerprint(cert.Certificate[1]),HandshakeTimeout:5,
	})
	if err!=nil { t.Fatal(err) }
	f.proxy=adapter.NewProxy(client)
	t.Cleanup(func(){_=f.proxy.Close()})
	return f
}

func TestNetVergeRouteLeaseHysteria2(t *testing.T) {
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	oa := nvWhistleNewOriginWithProof(t,"hy2-a-proof")
	ob := nvWhistleNewOriginWithProof(t,"hy2-b-proof")
	pa := nvWhistleNewOriginWithProof(t,"hy2-proxy-a")
	pb := nvWhistleNewOriginWithProof(t,"hy2-proxy-b")
	a := nvNewHysteria2Fixture(t,"hy2-a",oa,pa)
	b := nvNewHysteria2Fixture(t,"hy2-b",ob,pb)
	reject := adapter.NewProxy(outbound.NewReject())
	sel,err := G.NewSelector(G.GroupCommonOption{Name:"hy2-group",URL:"https://route.netverge.test/route-proof"},G.SelectorOption{DefaultSelected:a.proxy.Name()},reject,nvGroupProvider(t,"hy2-members",a.proxy,b.proxy))
	if err!=nil { t.Fatal(err) }
	group := adapter.NewProxy(sel)
	tunnel.UpdateProxies(map[string]C.Proxy{group.Name():group,a.proxy.Name():a.proxy,b.proxy.Name():b.proxy,reject.Name():reject},nil)
	tunnel.UpdateRules([]C.Rule{R.NewDomain(nvWhistleHost,group.Name())},nil,nil)
	dial := func(want C.Proxy) *nvLabLease {
		t.Helper()
		m := &C.Metadata{Type:C.TUN,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443}
		p,_,err := tunnel.NetVergeLabResolveMetadata(m)
		if err!=nil || p!=group { t.Fatalf("original Hysteria2 group decision: %v",err) }
		ctx,cancel := context.WithTimeout(context.Background(),nvLabTimeout)
		defer cancel()
		c,err := p.DialContext(ctx,m.Clone())
		if err!=nil { t.Fatal(err) }
		t.Cleanup(func(){_=c.Close()})
		trace,ok := N.FindUpstream[nvLabTypeTrace](c,nil)
		if !ok || !slices.Equal(trace.NetVergeLabAdapterTypes(),[]C.AdapterType{C.Hysteria2,C.Selector}) ||
			!slices.Equal([]string(c.Chains()),[]string{want.Name(),group.Name()}) {
			t.Fatal("actual Hysteria2 dial evidence missing")
		}
		if nvLabTypedEligible(group,c) { t.Fatal("experimental Hysteria2 admitted to eager-only gate") }
		t.Logf("native Hysteria2 %s NeedHandshake=%t",want.Name(),N.NeedHandshake(c))
		if !N.NeedHandshake(c) { t.Fatal("native Hysteria2 request header was not deferred") }
		// Only this verified fixture uses the experimental lazy admission.
		return nvLabLeaseVerifiedStream(t,c,nvWhistleAuthority)
	}
	la:=dial(a.proxy)
	if err=sel.Set(b.proxy.Name()); err!=nil { t.Fatal(err) }
	lb:=dial(b.proxy)
	if err=sel.Set(a.proxy.Name()); err!=nil { t.Fatal(err) }
	la2:=dial(a.proxy)
	roots:=filepath.Join(t.TempDir(),"hy2-roots.pem")
	caA,err:=os.ReadFile(oa.caPath)
	if err!=nil { t.Fatal(err) }
	caB,err:=os.ReadFile(ob.caPath)
	if err!=nil { t.Fatal(err) }
	if err=os.WriteFile(roots,append(caA,caB...),0600); err!=nil { t.Fatal(err) }
	ka,kb,ka2:=nvWhistlePassword(t),nvWhistlePassword(t),nvWhistlePassword(t)
	w:=nvWhistleLaunch(t,roots,map[string]*nvLabLease{ka:la,kb:lb,ka2:la2},nil)
	if a.decoded.Load()!=0 || b.decoded.Load()!=0 { t.Fatal("Hysteria2 request header emitted before first payload") }
	for _,f:=range []struct{
		key,proof string
		lease *nvLabLease
		origin *nvWhistleOrigin
		wantRequests int32
	}{{ka,"hy2-a-proof",la,oa,1},{kb,"hy2-b-proof",lb,ob,1},{ka2,"hy2-a-proof",la2,oa,2}} {
		auth:="Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+f.key))
		c,status,err:=nvWhistleConnect(w,nvWhistleAuthority,auth)
		if err!=nil || status!=200 { t.Fatalf("Hysteria2 ingress: %d %v",status,err) }
		peer,err:=nvWhistleRequestProof(c,w.root,f.proof)
		if err!=nil || string(peer)==string(f.origin.leaf) { t.Fatalf("Hysteria2 TLS proof: %v",err) }
		if N.NeedHandshake(f.lease.upstream) || !f.lease.Used() || f.origin.requests.Load()!=f.wantRequests { t.Fatal("original Hysteria2 stream not consumed exactly once") }
		_,status,err=nvWhistleConnect(w,nvWhistleAuthority,auth)
		if err!=nil || status!=403 { t.Fatalf("Hysteria2 lease replay: %d %v",status,err) }
	}
	for _,f:=range []struct{fixture *nvHysteria2Fixture; want int32}{{a,2},{b,1}} {
		if f.fixture.decoded.Load()!=f.want || f.fixture.bad.Load()!=0 {
			t.Fatalf("Hysteria2 authenticated stream counts: decoded=%d want=%d bad=%d",f.fixture.decoded.Load(),f.want,f.fixture.bad.Load())
		}
		f.fixture.sourcesMu.Lock()
		n:=len(f.fixture.sources)
		f.fixture.sourcesMu.Unlock()
		if n!=1 { t.Fatalf("unexpected client endpoint count: %d",n) }
	}
	if oa.leaked.Load() || ob.leaked.Load() { t.Fatal("credential leak") }
	t.Log("PASS: real Hysteria2 QUIC lazy streams preserved through one Whistle worker")
}
