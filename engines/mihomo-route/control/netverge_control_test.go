package tunnel_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/netvergecontrol"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

func TestNetVergeLocalController(t *testing.T){
	t.Cleanup(tunnel.NetVergeLabRestoreState())
	oldStatus:=tunnel.Status()
	t.Cleanup(func(){switch oldStatus{case tunnel.Running:tunnel.OnRunning();case tunnel.Inner:tunnel.OnInnerLoading();default:tunnel.OnSuspend()}})
	tunnel.OnRunning()
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	origin:=nvWhistleNewOriginWithProof(t,"controller-proof")
	var dials atomic.Int32
	a:=nvLabProxy(t,"controller-a",nvWhistleAuthority,origin.server.Listener.Addr().String(),&dials)
	reject:=adapter.NewProxy(outbound.NewReject())
	tunnel.UpdateProxies(map[string]C.Proxy{a.Name():a,reject.Name():reject},nil)
	tunnel.UpdateRules([]C.Rule{R.NewDomain(nvWhistleHost,a.Name())},nil,nil)
	worker:=nvWhistleLaunch(t,origin.caPath,map[string]*nvLabLease{},nil)
	secret:=nvWhistlePassword(t)
	control,err:=netvergecontrol.Start(0,secret)
	if err!=nil{t.Fatal(err)}
	t.Cleanup(control.Close)
	client:=&http.Client{Transport:&http.Transport{Proxy:nil,DisableKeepAlives:true},Timeout:5*time.Second}
	defer client.CloseIdleConnections()
	call:=func(method,token string,payload any)(int,map[string]any,error){
		body,_:=json.Marshal(payload)
		req,err:=http.NewRequest(method,"http://"+control.Addr()+"/v1/mitm",bytes.NewReader(body))
		if err!=nil{return 0,nil,err}
		req.Header.Set("Content-Type","application/json")
		req.Header.Set("Authorization","Bearer "+token)
		resp,err:=client.Do(req)
		if err!=nil{return 0,nil,err}
		defer resp.Body.Close()
		state:=map[string]any{}
		if resp.StatusCode==200{err=json.NewDecoder(resp.Body).Decode(&state)}
		return resp.StatusCode,state,err
	}
	check:=func(method,token string,payload any,want int)map[string]any{
		t.Helper()
		status,state,err:=call(method,token,payload)
		if err!=nil||status!=want{t.Fatalf("controller %s status=%d want=%d err=%v",method,status,want,err)}
		return state
	}
	check("GET","invalid",nil,401)
	state:=check("GET",secret,nil,200)
	if state["enabled"]!=false||state["protocol"]!=float64(1){t.Fatal("controller enabled by default")}
	raw,err:=base64.StdEncoding.DecodeString(worker.auth[len("Basic "):])
	if err!=nil{t.Fatal(err)}
	workerSecret:=string(raw[len("netverge:"):])
	settings:=netvergecontrol.Settings{Hosts:[]string{nvWhistleHost},WorkerPort:worker.port,WorkerSecret:workerSecret}
	check("PUT","invalid",settings,401)
	bad:=settings
	bad.WorkerSecret=nvWhistlePassword(t)
	check("PUT",secret,bad,503)
	run:=func(mitm bool)error{
		l,r:=net.Pipe()
		defer l.Close()
		defer r.Close()
		done:=make(chan struct{})
		go func(){defer close(done);tunnel.Tunnel.HandleTCPConn(r,&C.Metadata{Type:C.TUN,NetWork:C.TCP,Host:nvWhistleHost,DstPort:443})}()
		root:=origin.root
		if mitm{root=worker.root}
		peer,err:=nvWhistleRequestProof(l,root,"controller-proof")
		_=l.Close()
		select{case <-done:case <-time.After(5*time.Second):return errors.New("controller handoff not finished")}
		if err!=nil{return err}
		if bytes.Equal(peer,origin.leaf)==mitm{return errors.New("unexpected TLS peer")}
		return nil
	}
	if err=run(false);err!=nil{t.Fatal(err)}
	check("PUT",secret,settings,204)
	state=check("GET",secret,nil,200)
	if state["enabled"]!=true||state["workerSecret"]!=nil||state["workerPort"]!=nil{t.Fatal("controller status invalid")}
	if err=run(true);err!=nil{t.Fatal(err)}
	check("PUT",secret,bad,503)
	if err=run(true);err!=nil{t.Fatal(err)}
	check("DELETE",secret,nil,204)
	if err=run(false);err!=nil{t.Fatal(err)}
	if dials.Load()!=4||origin.requests.Load()!=4||origin.leaked.Load(){t.Fatal("controller changed original routes or leaked credentials")}
	t.Log("PASS: local authenticated controller enables native MITM, retains old state on bad worker, disables without profile rewrite")
}
