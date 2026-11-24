// Package netvergecontrol exposes a separate, opt-in loopback-only controller.
// Configuration is process-local, never read from an ordinary proxy profile.
package netvergecontrol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/routelease"
	"github.com/metacubex/mihomo/tunnel"
)

const protocol = 1
const apiPath = "/v1/mitm"
const workerPath = "/__netverge_routes"

type Settings struct {
	Hosts []string `json:"hosts"`
	WorkerPort int `json:"workerPort"`
	WorkerSecret string `json:"workerSecret"`
}

type Controller struct {
	mu sync.Mutex
	server *http.Server
	listener net.Listener
	secret string
	current *session
	closed bool
}

type session struct {
	settings Settings
	ctx context.Context
	cancel context.CancelFunc
	broker *routelease.Broker
	http *http.Client
}

func validSecret(s string) bool {
	if len(s)!=32{return false}
	v,err:=base64.RawURLEncoding.DecodeString(s)
	return err==nil && len(v)==24
}
func randomSecret()(string,error){
	var b [24]byte
	_,err:=rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]),err
}

// StartFromEnv consumes private launch settings, not runtime YAML. With no
// environment opt-in, the ordinary Mihomo behavior and listeners are unchanged.
func StartFromEnv()(func(),error){
	port,hasPort:=os.LookupEnv("NETVERGE_CORE_CONTROL_PORT")
	secret,hasSecret:=os.LookupEnv("NETVERGE_CORE_CONTROL_SECRET")
	_ = os.Unsetenv("NETVERGE_CORE_CONTROL_PORT")
	_ = os.Unsetenv("NETVERGE_CORE_CONTROL_SECRET")
	if !hasPort&&!hasSecret{return func(){},nil}
	p,err:=strconv.Atoi(port)
	if err!=nil||p<1024||p>65535||!hasSecret{return nil,errors.New("invalid NetVerge controller launch settings")}
	c,err:=Start(p,secret)
	if err!=nil{return nil,err}
	return c.Close,nil
}

func Start(port int,secret string)(*Controller,error){
	if !validSecret(secret)||port<0||port>65535||(port!=0&&port<1024){return nil,errors.New("invalid controller settings")}
	l,err:=net.Listen("tcp4",net.JoinHostPort("127.0.0.1",strconv.Itoa(port)))
	if err!=nil{return nil,err}
	c:=&Controller{listener:l,secret:secret}
	c.server=&http.Server{Handler:http.HandlerFunc(c.serve),ReadHeaderTimeout:2*time.Second,ReadTimeout:5*time.Second,WriteTimeout:6*time.Second,IdleTimeout:2*time.Second,MaxHeaderBytes:4096}
	c.server.SetKeepAlivesEnabled(false)
	go func(){_ = c.server.Serve(l);c.Close()}()
	return c,nil
}
func(c *Controller) Addr() string{return c.listener.Addr().String()}

func(c *Controller) Close(){
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed{return}
	c.closed=true
	c.disableLocked()
	_=c.listener.Close()
	_=c.server.Close()
}
func(c *Controller) disableLocked(){
	_=tunnel.SetNetVergeRouteHandler(nil,nil)
	if c.current!=nil{c.current.close();c.current=nil}
}
func(c *Controller) serve(w http.ResponseWriter,r *http.Request){
	w.Header().Set("Cache-Control","no-store")
	w.Header().Set("Connection","close")
	if r.Host!=c.Addr()||r.URL.Path!=apiPath||r.URL.RawQuery!=""||r.Header.Get("Origin")!=""{
		w.WriteHeader(http.StatusForbidden);return
	}
	auth:=r.Header.Values("Authorization")
	if len(auth)!=1||subtle.ConstantTimeCompare([]byte(auth[0]),[]byte("Bearer "+c.secret))!=1{
		w.WriteHeader(http.StatusUnauthorized);return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed{w.WriteHeader(http.StatusServiceUnavailable);return}
	switch r.Method{
	case http.MethodGet:
		hosts:=[]string{}
		if c.current!=nil{hosts=c.current.settings.Hosts}
		w.Header().Set("Content-Type","application/json")
		_ = json.NewEncoder(w).Encode(struct{
			Protocol int `json:"protocol"`
			Enabled bool `json:"enabled"`
			Hosts []string `json:"hosts"`
		}{protocol,c.current!=nil,hosts})
	case http.MethodDelete:
		c.disableLocked()
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut:
		if r.Header.Get("Content-Type")!="application/json"{w.WriteHeader(http.StatusUnsupportedMediaType);return}
		var settings Settings
		dec:=json.NewDecoder(http.MaxBytesReader(w,r.Body,16384))
		dec.DisallowUnknownFields()
		if dec.Decode(&settings)!=nil||dec.Decode(new(any))!=io.EOF||
			!validSecret(settings.WorkerSecret)||settings.WorkerSecret==c.secret||
			settings.WorkerPort<1024||settings.WorkerPort>65535||
			settings.WorkerPort==c.listener.Addr().(*net.TCPAddr).Port||
			len(settings.Hosts)==0||len(settings.Hosts)>64{
			w.WriteHeader(http.StatusBadRequest);return
		}
		s,err:=newSession(settings)
		if err!=nil{w.WriteHeader(http.StatusServiceUnavailable);return}
		// Authenticate the ready worker and verify its authority allowlist
		// before changing the current generation. Failure preserves old state.
		if err=s.ready(r.Context());err!=nil{s.close();w.WriteHeader(http.StatusServiceUnavailable);return}
		if err=tunnel.SetNetVergeRouteHandler(settings.Hosts,s.handle);err!=nil{s.close();w.WriteHeader(http.StatusBadRequest);return}
		old:=c.current
		c.current=s
		if old!=nil{old.close()}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
func newSession(settings Settings)(*session,error){
	b,err:=routelease.NewBroker(64,15*time.Second,40*time.Second)
	if err!=nil{return nil,err}
	ctx,cancel:=context.WithCancel(context.Background())
	tr:=&http.Transport{Proxy:nil,DisableKeepAlives:true,DialContext:(&net.Dialer{Timeout:2*time.Second}).DialContext}
	return &session{settings:settings,ctx:ctx,cancel:cancel,broker:b,http:&http.Client{Transport:tr,Timeout:3*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}},nil
}
func(s *session) close(){
	s.cancel()
	s.broker.Close()
	s.http.CloseIdleConnections()
}
func(s *session) workerAddr()string{return net.JoinHostPort("127.0.0.1",strconv.Itoa(s.settings.WorkerPort))}
func(s *session) workerRequest(ctx context.Context,method string,payload any)(*http.Response,error){
	var body io.Reader
	if payload!=nil{
		raw,err:=json.Marshal(payload)
		if err!=nil{return nil,err}
		body=bytes.NewReader(raw)
	}
	req,err:=http.NewRequestWithContext(ctx,method,"http://"+s.workerAddr()+workerPath,body)
	if err!=nil{return nil,err}
	req.Header.Set("Proxy-Authorization","Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+s.settings.WorkerSecret)))
	if payload!=nil{req.Header.Set("Content-Type","application/json")}
	resp,err:=s.http.Do(req)
	if err!=nil{return nil,errors.New("worker control unavailable")}
	return resp,nil
}
func(s *session) ready(ctx context.Context)error{
	resp,err:=s.workerRequest(ctx,http.MethodGet,nil)
	if err!=nil{return err}
	defer resp.Body.Close()
	var state struct{Protocol int `json:"protocol"`; Hosts []string `json:"hosts"`}
	if resp.StatusCode!=200||json.NewDecoder(io.LimitReader(resp.Body,32768)).Decode(&state)!=nil||state.Protocol!=protocol{
		return errors.New("worker not ready")
	}
	allowed:=make(map[string]bool,len(state.Hosts))
	for _,h:=range state.Hosts{allowed[h]=true}
	for _,h:=range s.settings.Hosts{if !allowed[h]{return errors.New("worker authority mismatch")}}
	return nil
}
func(s *session) change(ctx context.Context,method string,payload any,want int)error{
	resp,err:=s.workerRequest(ctx,method,payload)
	if err!=nil{return err}
	defer resp.Body.Close()
	if resp.StatusCode!=want{return errors.New("worker registration refused")}
	return nil
}
type registration struct{
	Authority string `json:"authority"`
	Ingress string `json:"ingress"`
	Password string `json:"password"`
	Port int `json:"port"`
}

func(s *session) handle(client net.Conn,up C.Conn,m *C.Metadata,_ C.Rule)error{
	if s.ctx.Err()!=nil{return errors.New("MITM generation closed")}
	// A generation change closes both directions, including a handler
	// captured before a slow outbound dial completed.
	ctx,cancel:=context.WithTimeout(s.ctx,45*time.Second)
	defer cancel()
	stopClient:=context.AfterFunc(ctx,func(){_=client.Close()})
	defer stopClient()
	authority:=net.JoinHostPort(m.Host,"443")
	lease,err:=s.broker.Open(ctx,up,authority)
	if err!=nil{return err}
	defer lease.Close()
	id,err:=randomSecret()
	if err!=nil{return err}
	// Attempt DELETE even if the POST result was ambiguous (e.g. timeout).
	defer func(){
		cleanup,cancel:=context.WithTimeout(context.Background(),2*time.Second)
		defer cancel()
		if s.change(cleanup,http.MethodDelete,map[string]string{"ingress":id},204)!=nil{
			log.Warnln("[NetVerge MITM] worker registration cleanup unavailable")
		}
	}()
	entry:=registration{authority,id,lease.Password(),lease.Addr().(*net.TCPAddr).Port}
	if err=s.change(ctx,http.MethodPost,entry,201);err!=nil{return err}
	raw,err:=(&net.Dialer{Timeout:3*time.Second}).DialContext(ctx,"tcp4",s.workerAddr())
	if err!=nil{return errors.New("worker ingress unavailable")}
	defer raw.Close()
	stopRaw:=context.AfterFunc(ctx,func(){_=raw.Close()})
	defer stopRaw()
	_=raw.SetDeadline(time.Now().Add(5*time.Second))
	token:="Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+id))
	if _,err=fmt.Fprintf(raw,"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",authority,authority,token);err!=nil{return errors.New("worker ingress write failed")}
	reader:=bufio.NewReader(raw)
	resp,err:=http.ReadResponse(reader,&http.Request{Method:http.MethodConnect})
	if err!=nil||resp.StatusCode!=200{return errors.New("worker ingress rejected")}
	_=raw.SetDeadline(time.Time{})
	done:=make(chan struct{})
	go func(){defer close(done);_,_=io.Copy(raw,client);_=raw.Close();_=client.Close()}()
	_,_=io.Copy(client,reader)
	_=client.Close()
	_=raw.Close()
	<-done
	if !lease.Used(){return errors.New("original stream not consumed")}
	return nil
}
