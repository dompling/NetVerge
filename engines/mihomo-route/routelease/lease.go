// Package routelease hands an already-dialed stream to an authenticated
// local HTTP CONNECT consumer. It never resolves, dials or changes a route.
// The caller must perform admission on the original adapter result first.
package routelease

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Broker struct {
	mu sync.Mutex
	closed bool
	max int
	pending, active time.Duration
	leases map[*Lease]struct{}
}

// NewBroker bounds both outstanding capabilities and their lifetime.
func NewBroker(max int, pending, active time.Duration) (*Broker,error) {
	if max<1 || max>4096 || pending<=0 || active<=0 || pending>time.Hour || active>24*time.Hour {
		return nil,errors.New("invalid lease limits")
	}
	return &Broker{max:max,pending:pending,active:active,leases:make(map[*Lease]struct{})},nil
}

type Lease struct {
	broker *Broker
	listener net.Listener
	server *http.Server
	upstream net.Conn
	authority, password, token string
	used atomic.Bool
	mu sync.Mutex
	client net.Conn
	closed bool
	once sync.Once
	done chan struct{}
}

func validAuthority(authority string) bool {
	if len(authority)>260 || strings.ContainsAny(authority," /\\@?#\r\n\t") { return false }
	host,port,err:=net.SplitHostPort(authority)
	if err!=nil || host=="" { return false }
	p,err:=strconv.Atoi(port)
	if err!=nil || p<1 || p>65535 || strconv.Itoa(p)!=port { return false }
	if net.ParseIP(host)!=nil { return true }
	for _,label:=range strings.Split(host,".") {
		if len(label)==0 || len(label)>63 || label[0]=='-' || label[len(label)-1]=='-' {return false}
		for _,c:=range label { if !(c>='a'&&c<='z'||c>='0'&&c<='9'||c=='-') {return false} }
	}
	return true
}

// Open transfers ownership of upstream only on success. No credentials are
// logged. Revoking or expiring a lease closes the original stream.
func (b *Broker) Open(ctx context.Context, upstream net.Conn, authority string) (*Lease,error) {
	if ctx==nil || upstream==nil || !validAuthority(authority) {return nil,errors.New("invalid lease input")}
	if err:=ctx.Err();err!=nil{return nil,err}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || len(b.leases)>=b.max {return nil,errors.New("lease broker unavailable")}
	listener,err:=net.Listen("tcp4","127.0.0.1:0")
	if err!=nil{return nil,err}
	var secret [24]byte
	if _,err=rand.Read(secret[:]);err!=nil{listener.Close();return nil,err}
	password:=base64.RawURLEncoding.EncodeToString(secret[:])
	l:=&Lease{broker:b,listener:listener,upstream:upstream,authority:authority,password:password,
		token:"Basic "+base64.StdEncoding.EncodeToString([]byte("netverge:"+password)),done:make(chan struct{})}
	l.server=&http.Server{ReadHeaderTimeout:2*time.Second,ReadTimeout:3*time.Second,
		WriteTimeout:3*time.Second,IdleTimeout:2*time.Second,MaxHeaderBytes:4096,Handler:http.HandlerFunc(l.handle)}
	l.server.SetKeepAlivesEnabled(false)
	b.leases[l]=struct{}{}
	go func(){_ = l.server.Serve(listener); l.Close()}()
	go func(){
		timer:=time.NewTimer(b.pending+b.active)
		defer timer.Stop()
		pending:=time.NewTimer(b.pending)
		defer pending.Stop()
		select {
		case <-ctx.Done():l.Close();return
		case <-l.done:return
		case <-pending.C:
			if !l.used.Load(){l.Close();return}
		}
		select {case <-ctx.Done():l.Close();case <-timer.C:l.Close();case <-l.done:}
	}()
	return l,nil
}

func (l *Lease) Addr() net.Addr {return l.listener.Addr()}
func (l *Lease) Password() string {return l.password}
func (l *Lease) Used() bool {return l.used.Load()}

func (l *Lease) handle(w http.ResponseWriter,r *http.Request) {
	auth:=r.Header.Values("Proxy-Authorization")
	if len(auth)!=1 || subtle.ConstantTimeCompare([]byte(auth[0]),[]byte(l.token))!=1 {
		w.WriteHeader(http.StatusProxyAuthRequired);return
	}
	if r.Method!=http.MethodConnect || r.RequestURI!=l.authority || r.Host!=l.authority ||
		r.ContentLength!=0 || len(r.TransferEncoding)!=0 {
		w.WriteHeader(http.StatusForbidden);return
	}
	l.mu.Lock()
	if l.closed || !l.used.CompareAndSwap(false,true) {
		l.mu.Unlock();w.WriteHeader(http.StatusForbidden);return
	}
	client,rw,err:=w.(http.Hijacker).Hijack()
	if err!=nil {l.mu.Unlock();l.Close();return}
	l.client=client
	l.mu.Unlock()
	defer client.Close()
	defer l.upstream.Close()
	deadline:=time.Now().Add(l.broker.active)
	if client.SetDeadline(deadline)!=nil || l.upstream.SetDeadline(deadline)!=nil{return}
	if _,err=rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n");err!=nil{return}
	if err=rw.Flush();err!=nil{return}
	// Preserve the complete original wrapper chain, including first-write
	// callbacks and QUIC stream ownership. Never bypass buffered input.
	done:=make(chan struct{})
	go func(){defer close(done);_,_=io.Copy(l.upstream,rw.Reader);_=l.upstream.Close();_=client.Close()}()
	_,_=io.Copy(client,l.upstream)
	_=client.Close()
	_=l.upstream.Close()
	<-done
}

func (l *Lease) Close() {
	l.once.Do(func(){
		l.mu.Lock()
		l.closed=true
		client:=l.client
		l.mu.Unlock()
		_=l.listener.Close()
		_=l.server.Close()
		if client!=nil{_=client.Close()}
		_=l.upstream.Close()
		l.broker.mu.Lock()
		delete(l.broker.leases,l)
		l.broker.mu.Unlock()
		close(l.done)
	})
}
func (b *Broker) Close() {
	b.mu.Lock()
	b.closed=true
	leases:=make([]*Lease,0,len(b.leases))
	for l:=range b.leases{leases=append(leases,l)}
	b.mu.Unlock()
	for _,l:=range leases{l.Close()}
}
