// Real upstream VMess AEAD client and service on isolated loopback endpoints.
package tunnel_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	G "github.com/metacubex/mihomo/adapter/outboundgroup"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
	vmess "github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing/common/auth"
	M "github.com/metacubex/sing/common/metadata"
	SN "github.com/metacubex/sing/common/network"
)

type nvVMessFixture struct {
	proxy C.Proxy
	accepted atomic.Int32
	decoded atomic.Int32
	bad atomic.Int32
	origin *nvWhistleOrigin
	user string
}

func (f *nvVMessFixture) NewConnection(ctx context.Context,stream net.Conn,m M.Metadata) error {
	defer stream.Close()
	user,ok:=auth.UserFromContext[string](ctx)
	if !ok || user!=f.user || m.Destination.String()!=nvWhistleAuthority {
		f.bad.Add(1)
		return errors.New("unexpected VMess user or destination")
	}
	up,err:=net.DialTimeout("tcp",f.origin.server.Listener.Addr().String(),nvLabTimeout)
	if err!=nil { f.bad.Add(1); return err }
	defer up.Close()
	_ = up.SetDeadline(time.Now().Add(75*time.Second))
	f.decoded.Add(1)
	nvLabRelay(stream,stream,up)
	return nil
}
func (f *nvVMessFixture) NewPacketConnection(ctx context.Context,c SN.PacketConn,m M.Metadata) error {
	defer c.Close()
	f.bad.Add(1)
	return errors.New("unexpected VMess UDP")
}
func (f *nvVMessFixture) NewError(ctx context.Context,err error) {
	f.bad.Add(1)
}
func nvNewVMessFixture(t *testing.T,name,cipher string,origin *nvWhistleOrigin)*nvVMessFixture {
	t.Helper()
	id,err:=uuid.NewV4()
	if err!=nil { t.Fatal(err) }
	f:=&nvVMessFixture{origin:origin,user:name}
	service:=vmess.NewService[string](f,vmess.ServiceWithDisableHeaderProtection())
	if err=service.UpdateUsers([]string{name},[]string{id.String()},[]int{0}); err!=nil { t.Fatal(err) }
	if err=service.Start(); err!=nil { t.Fatal(err) }
	t.Cleanup(func(){_=service.Close()})
	l,err:=net.Listen("tcp4","127.0.0.1:0")
	if err!=nil { t.Fatal(err) }
	var wg sync.WaitGroup
	done:=make(chan struct{})
	go func(){
		defer close(done)
		for {
			c,err:=l.Accept()
			if err!=nil { return }
			f.accepted.Add(1)
			wg.Add(1)
			go func(raw net.Conn){
				defer wg.Done()
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(75*time.Second))
				if err:=service.NewConnection(context.Background(),raw,M.Metadata{Protocol:"vmess",Source:M.SocksaddrFromNet(raw.RemoteAddr())}); err!=nil {
					f.bad.Add(1)
				}
			}(c)
		}
	}()
	t.Cleanup(func(){_=l.Close(); <-done; wg.Wait()})
	host,portString,err:=net.SplitHostPort(l.Addr().String())
	if err!=nil { t.Fatal(err) }
	port,err:=strconv.Atoi(portString)
	if err!=nil { t.Fatal(err) }
	client,err:=outbound.NewVmess(outbound.VmessOption{Name:name,Server:host,Port:port,UUID:id.String(),Cipher:cipher,AlterID:0})
	if err!=nil { t.Fatal(err) }
	f.proxy=adapter.NewProxy(client)
	t.Cleanup(func(){_=f.proxy.Close()})
	return f
}

func TestNetVergeRouteLeaseVmess(t *testing.T) {
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	oa := nvWhistleNewOriginWithProof(t,"vmess-aes-proof")
	ob := nvWhistleNewOriginWithProof(t,"vmess-chacha-proof")
	a := nvNewVMessFixture(t,"vmess-aes","aes-128-gcm",oa)
	b := nvNewVMessFixture(t,"vmess-chacha","chacha20-poly1305",ob)
	reject := adapter.NewProxy(outbound.NewReject())
	sel,err := G.NewSelector(G.GroupCommonOption{Name:"vmess-group",URL:"https://route.netverge.test/route-proof"},G.SelectorOption{DefaultSelected:a.proxy.Name()},reject,nvGroupProvider(t,"vmess-members",a.proxy,b.proxy))
	if err!=nil { t.Fatal(err) }
	group := adapter.NewProxy(sel)
	tunnel.UpdateProxies(map[string]C.Proxy{group.Name():group,a.proxy.Name():a.proxy,b.proxy.Name():b.proxy,reject.Name():reject},nil)
	tunnel.UpdateRules([]C.Rule{R.NewDomain(nvWhistleHost,group.Name())},nil,nil)
	dial := func(want C.Proxy) *nvLabLease {
		t.Helper()
		m := &C.Metadata{Type:C.TUN,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443}
		p,_,err := tunnel.NetVergeLabResolveMetadata(m)
		if err!=nil || p!=group { t.Fatalf("original VMess group decision: %v",err) }
		ctx,cancel := context.WithTimeout(context.Background(),nvLabTimeout)
		defer cancel()
		c,err := p.DialContext(ctx,m.Clone())
		if err!=nil { t.Fatal(err) }
		t.Cleanup(func(){_=c.Close()})
		trace,ok := N.FindUpstream[nvLabTypeTrace](c,nil)
		if !ok || !slices.Equal(trace.NetVergeLabAdapterTypes(),[]C.AdapterType{C.Vmess,C.Selector}) ||
			!slices.Equal([]string(c.Chains()),[]string{want.Name(),group.Name()}) {
			t.Fatal("actual VMess dial evidence missing")
		}
		if nvLabTypedEligible(group,c) { t.Fatal("experimental VMess admitted to eager-only gate") }
		t.Logf("native VMess %s NeedHandshake=%t",want.Name(),N.NeedHandshake(c))
		// Plain AEAD may be eager. Do not claim lazy support from this result.
		return nvLabLeaseVerifiedStream(t,c,nvWhistleAuthority)
	}
	la:=dial(a.proxy)
	if err=sel.Set(b.proxy.Name()); err!=nil { t.Fatal(err) }
	lb:=dial(b.proxy)
	if err=sel.Set(a.proxy.Name()); err!=nil { t.Fatal(err) }
	roots:=filepath.Join(t.TempDir(),"vmess-roots.pem")
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
	}{{ka,"vmess-aes-proof",la,oa},{kb,"vmess-chacha-proof",lb,ob}} {
		auth:="Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+f.key))
		c,status,err:=nvWhistleConnect(w,nvWhistleAuthority,auth)
		if err!=nil || status!=200 { t.Fatalf("VMess ingress: %d %v",status,err) }
		peer,err:=nvWhistleRequestProof(c,w.root,f.proof)
		if err!=nil || string(peer)==string(f.origin.leaf) { t.Fatalf("VMess TLS proof: %v",err) }
		if !f.lease.Used() || f.origin.requests.Load()!=1 { t.Fatal("original VMess stream not consumed exactly once") }
		_,status,err=nvWhistleConnect(w,nvWhistleAuthority,auth)
		if err!=nil || status!=403 { t.Fatalf("VMess lease replay: %d %v",status,err) }
	}
	for _,f:=range []*nvVMessFixture{a,b} {
		if f.accepted.Load()!=1 || f.decoded.Load()!=1 || f.bad.Load()!=0 {
			t.Fatalf("VMess connection or encrypted destination proof failed: accepted=%d decoded=%d bad=%d",f.accepted.Load(),f.decoded.Load(),f.bad.Load())
		}
	}
	if oa.leaked.Load() || ob.leaked.Load() { t.Fatal("credential leak") }
	t.Log("PASS: real AES-GCM and ChaCha20-Poly1305 VMess streams preserved through one Whistle worker")
}
