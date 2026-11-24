package tunnel_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/routelease"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

func TestNetVergeDynamicWhistleRegistry(t *testing.T) {
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	oldStatus:=tunnel.Status()
	t.Cleanup(func(){switch oldStatus{case tunnel.Running:tunnel.OnRunning();case tunnel.Inner:tunnel.OnInnerLoading();default:tunnel.OnSuspend()}})
	t.Cleanup(func(){_=tunnel.SetNetVergeRouteHandler(nil,nil)})
	tunnel.OnRunning()
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	oa:=nvWhistleNewOriginWithProof(t,"dynamic-a")
	ob:=nvWhistleNewOriginWithProof(t,"dynamic-b")
	var ca,cb atomic.Int32
	a:=nvLabProxy(t,"dynamic-a",nvWhistleAuthority,oa.server.Listener.Addr().String(),&ca)
	b:=nvLabProxy(t,"dynamic-b",nvWhistleAuthority,ob.server.Listener.Addr().String(),&cb)
	reject:=adapter.NewProxy(outbound.NewReject())
	tunnel.UpdateProxies(map[string]C.Proxy{a.Name():a,b.Name():b,reject.Name():reject},nil)
	ruleA,err:=R.NewProcess("dynamic-a",a.Name(),C.ProcessName)
	if err!=nil{t.Fatal(err)}
	ruleB,err:=R.NewProcess("dynamic-b",b.Name(),C.ProcessName)
	if err!=nil{t.Fatal(err)}
	tunnel.UpdateRules([]C.Rule{ruleA,ruleB,R.NewDomain(nvWhistleHost,reject.Name())},nil,nil)
	roots:=filepath.Join(t.TempDir(),"roots.pem")
	ra,err:=os.ReadFile(oa.caPath);if err!=nil{t.Fatal(err)}
	rb,err:=os.ReadFile(ob.caPath);if err!=nil{t.Fatal(err)}
	if err=os.WriteFile(roots,append(ra,rb...),0600);err!=nil{t.Fatal(err)}
	// No routes exist at worker startup.
	w:=nvWhistleLaunch(t,roots,map[string]*nvLabLease{},nil)
	broker,err:=routelease.NewBroker(8,30*time.Second,20*time.Second)
	if err!=nil{t.Fatal(err)}
	t.Cleanup(broker.Close)
	transport:=&http.Transport{DisableKeepAlives:true}
	defer transport.CloseIdleConnections()
	control:=&http.Client{Transport:transport,Timeout:3*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
	request:=func(method,auth string,entry map[string]any)(int,error){
		body,err:=json.Marshal(entry);if err!=nil{return 0,err}
		req,err:=http.NewRequest(method,fmt.Sprintf("http://127.0.0.1:%d/__netverge_routes",w.port),bytes.NewReader(body))
		if err!=nil{return 0,err}
		req.Header.Set("Content-Type","application/json")
		req.Header.Set("Proxy-Authorization",auth)
		resp,err:=control.Do(req);if err!=nil{return 0,err}
		defer resp.Body.Close()
		return resp.StatusCode,nil
	}
	invalid:=map[string]any{"authority":"wrong.netverge.test:443","ingress":nvWhistlePassword(t),"password":nvWhistlePassword(t),"port":22222}
	if code,err:=request("POST","Basic invalid",invalid);err!=nil||code!=403{t.Fatalf("invalid control authorization %d %v",code,err)}
	if code,err:=request("POST",w.auth,invalid);err!=nil||code!=400{t.Fatalf("wrong control authority %d %v",code,err)}
	keys:=map[string]string{"dynamic-a":nvWhistlePassword(t),"dynamic-b":nvWhistlePassword(t)}
	var count atomic.Int32
	var handlerErrors atomic.Int32
	var removeErrors atomic.Int32
	var revoke atomic.Bool
	var idMu sync.Mutex
	ids:=[]string{}
	handler:=func(client net.Conn,up C.Conn,m *C.Metadata,rule C.Rule)(err error){
		defer func(){if err!=nil{handlerErrors.Add(1)}}()
		if rule==nil||rule.RuleType()!=C.ProcessName||len(up.Chains())!=1||up.Chains()[0]!=m.Process{return errors.New("original selection lost")}
		lease,err:=broker.Open(context.Background(),up,nvWhistleAuthority)
		if err!=nil{return err}
		defer lease.Close()
		id:=keys[m.Process]
		if count.Add(1)>2 {id=nvWhistlePassword(t)}
		entry:=map[string]any{"authority":nvWhistleAuthority,"ingress":id,"password":lease.Password(),"port":lease.Addr().(*net.TCPAddr).Port}
		code,err:=request("POST",w.auth,entry)
		if err!=nil||code!=201{return errors.New("dynamic registration failed")}
		defer func(){if code,err:=request("DELETE",w.auth,map[string]any{"ingress":id});err!=nil||code!=204{removeErrors.Add(1)}}()
		idMu.Lock();ids=append(ids,id);idMu.Unlock()
		if code,err=request("POST",w.auth,entry);err!=nil||code!=409{return errors.New("duplicate registration admitted")}
		if revoke.Load(){
			if code,err=request("DELETE",w.auth,map[string]any{"ingress":id});err!=nil||code!=204{return errors.New("revocation failed")}
		}
		token:="Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+id))
		raw,status,err:=nvWhistleConnect(w,nvWhistleAuthority,token)
		if err!=nil||status!=200{return errors.New("dynamic ingress denied")}
		defer raw.Close()
		nvLabRelay(client,client,raw)
		if !lease.Used(){return errors.New("original lease not consumed")}
		return nil
	}
	if err=tunnel.SetNetVergeRouteHandler([]string{nvWhistleHost},handler);err!=nil{t.Fatal(err)}
	run:=func(proc,proof string)error{
		left,right:=net.Pipe()
		defer left.Close()
		defer right.Close()
		done:=make(chan struct{})
		go func(){defer close(done);tunnel.Tunnel.HandleTCPConn(right,&C.Metadata{Type:C.TUN,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443,Process:proc})}()
		peer,err:=nvWhistleRequestProof(left,w.root,proof)
		_=left.Close()
		select{case <-done:case <-time.After(4*time.Second):return errors.New("native handoff timed out")}
		if err==nil && (bytes.Equal(peer,oa.leaf)||bytes.Equal(peer,ob.leaf)){return errors.New("MITM certificate missing")}
		return err
	}
	results:=make(chan error,2)
	go func(){results<-run("dynamic-a","dynamic-a")}()
	go func(){results<-run("dynamic-b","dynamic-b")}()
	for i:=0;i<2;i++{if err:=<-results;err!=nil{t.Fatal(err)}}
	if ca.Load()!=1||cb.Load()!=1||oa.requests.Load()!=1||ob.requests.Load()!=1||handlerErrors.Load()!=0||removeErrors.Load()!=0{t.Fatal("concurrent dynamic routes crossed or redialed")}
	for _,id:=range ids{
		token:="Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+id))
		raw,status,err:=nvWhistleConnect(w,nvWhistleAuthority,token)
		if raw!=nil{raw.Close()}
		if err!=nil||status!=407{t.Fatal("removed registration still usable")}
	}
	revoke.Store(true)
	if err=run("dynamic-a","dynamic-a");err==nil{t.Fatal("revoked route succeeded")}
	if ca.Load()!=2||cb.Load()!=1||oa.requests.Load()!=1||ob.requests.Load()!=1||handlerErrors.Load()!=1||removeErrors.Load()!=0{t.Fatal("revocation retried or fell back")}
	if oa.leaked.Load()||ob.leaked.Load(){t.Fatal("credential leakage")}
	t.Log("PASS: native TCP handoff through one dynamic Whistle worker; concurrent route isolation, authenticated registration, revocation and no fallback")
}
