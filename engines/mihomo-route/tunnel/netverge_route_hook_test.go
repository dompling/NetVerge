package tunnel_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/routelease"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

func TestNetVergeNativeTCPHandoff(t *testing.T) {
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	oldStatus:=tunnel.Status()
	t.Cleanup(func(){switch oldStatus{case tunnel.Running:tunnel.OnRunning();case tunnel.Inner:tunnel.OnInnerLoading();default:tunnel.OnSuspend()}})
	t.Cleanup(func(){_=tunnel.SetNetVergeRouteHandler(nil,nil)})
	tunnel.OnRunning()
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	origin:=nvWhistleNewOriginWithProof(t,"native-proof")
	cert:=nvWhistleNewOriginWithProof(t,"native-proxy-ca")
	v:=nvNewVLESSFixture(t,"native-vless",origin,cert)
	reject:=adapter.NewProxy(outbound.NewReject())
	tunnel.UpdateProxies(map[string]C.Proxy{v.proxy.Name():v.proxy,reject.Name():reject},nil)
	processRule,err:=R.NewProcess("native-selected",v.proxy.Name(),C.ProcessName)
	if err!=nil{t.Fatal(err)}
	blockRule,err:=R.NewProcess("native-blocked",reject.Name(),C.ProcessName)
	if err!=nil{t.Fatal(err)}
	tunnel.UpdateRules([]C.Rule{blockRule,processRule,R.NewDomain(nvWhistleHost,v.proxy.Name())},nil,nil)
	broker,err:=routelease.NewBroker(4,10*time.Second,10*time.Second)
	if err!=nil{t.Fatal(err)}
	t.Cleanup(broker.Close)
	var calls atomic.Int32
	var fail atomic.Bool
	var observed atomic.Bool
	var handlerErrors atomic.Int32
	handler:=func(client net.Conn,upstream C.Conn,m *C.Metadata,rule C.Rule) (err error) {
		calls.Add(1)
		defer func(){if err!=nil{handlerErrors.Add(1)}}()
		if m.Process!="native-selected" || rule==nil || rule.RuleType()!=C.ProcessName ||
			!N.NeedHandshake(upstream) || len(upstream.Chains())!=1 || upstream.Chains()[0]!=v.proxy.Name() {
			return errors.New("original metadata, rule or lazy stream missing")
		}
		observed.Store(true)
		if fail.Load(){return errors.New("controlled handoff failure")}
		lease,err:=broker.Open(context.Background(),upstream,nvWhistleAuthority)
		if err!=nil{return err}
		defer lease.Close()
		raw,err:=net.DialTimeout("tcp",lease.Addr().String(),nvLabTimeout)
		if err!=nil{return err}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(nvLabTimeout))
		token:="Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+lease.Password()))
		if _,err=fmt.Fprintf(raw,"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",nvWhistleAuthority,nvWhistleAuthority,token);err!=nil{return err}
		reader:=bufio.NewReader(raw)
		resp,err:=http.ReadResponse(reader,&http.Request{Method:http.MethodConnect})
		if err!=nil{return err}
		if resp.StatusCode!=200{return errors.New("lease refused")}
		nvLabRelay(client,client,nvLabBufferedConn{Conn:raw,reader:reader})
		if !lease.Used(){return errors.New("original stream unused")}
		return nil
	}
	run:=func(typ C.Type,proc string,want bool){
		t.Helper()
		left,right:=net.Pipe()
		done:=make(chan struct{})
		go func(){
			defer close(done)
			tunnel.Tunnel.HandleTCPConn(right,&C.Metadata{Type:typ,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443,Process:proc})
		}()
		_,err:=nvWhistleRequestProof(left,origin.root,"native-proof")
		_=left.Close()
		select{case <-done:case <-time.After(2*time.Second):_=right.Close();t.Fatal("native handler did not finish")}
		if (err==nil)!=want{t.Fatalf("native TLS result: want success=%t err=%v",want,err)}
	}
	// Disabled registration preserves the normal native first-write path.
	run(C.TUN,"native-selected",true)
	if calls.Load()!=0 || v.decoded.Load()!=1 || origin.requests.Load()!=1{t.Fatal("disabled hook changed native forwarding")}
	if err=tunnel.SetNetVergeRouteHandler([]string{nvWhistleHost},handler);err!=nil{t.Fatal(err)}
	run(C.TUN,"native-selected",true)
	if calls.Load()!=1 || !observed.Load() || handlerErrors.Load()!=0 || v.decoded.Load()!=2 || origin.requests.Load()!=2 {
		t.Fatal("native hook did not preserve the selected lazy stream")
	}
	// REJECT is never admitted even for a listed host.
	run(C.TUN,"native-blocked",false)
	if calls.Load()!=1 || origin.requests.Load()!=2{t.Fatal("native reject entered hook")}
	// A consumed admission must not fall back or retry to the origin.
	fail.Store(true)
	run(C.TUN,"native-selected",false)
	if calls.Load()!=2 || handlerErrors.Load()!=1 || origin.requests.Load()!=2 || v.decoded.Load()!=2{t.Fatal("handoff failure bypassed or retried")}
	if err=tunnel.SetNetVergeRouteHandler(nil,nil);err!=nil{t.Fatal(err)}
	run(C.TUN,"native-selected",true)
	if calls.Load()!=2 || origin.requests.Load()!=3 || v.decoded.Load()!=3{t.Fatal("disable did not restore native forwarding")}
	t.Log("PASS: native TCP path, original process rule, deferred VLESS first write, reject isolation and no fallback on handoff failure")
}
