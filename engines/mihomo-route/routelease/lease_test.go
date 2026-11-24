package routelease

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestBrokerBoundsAndOwnership(t *testing.T){
	b,err:=NewBroker(1,time.Second,time.Second)
	if err!=nil{t.Fatal(err)}
	defer b.Close()
	left,right:=net.Pipe()
	defer right.Close()
	l,err:=b.Open(context.Background(),left,"route.netverge.test:443")
	if err!=nil{t.Fatal(err)}
	if l.Used()||l.Addr().(*net.TCPAddr).IP.String()!="127.0.0.1"{t.Fatal("invalid new lease")}
	x,y:=net.Pipe()
	defer x.Close();defer y.Close()
	if _,err=b.Open(context.Background(),x,"route.netverge.test:443");err==nil{t.Fatal("capacity exceeded")}
	// Failed Open leaves the caller's connection owned by the caller.
	go y.Write([]byte("x"))
	_ = x.SetReadDeadline(time.Now().Add(time.Second))
	p:=make([]byte,1)
	if _,err=x.Read(p);err!=nil||p[0]!='x'{t.Fatal("failed open stole caller connection")}
	l.Close()
	l.Close()
	if _,err=right.Read(p);err==nil{t.Fatal("revocation left upstream open")}
	next,peer:=net.Pipe()
	defer peer.Close()
	if _,err=b.Open(context.Background(),next,"route.netverge.test:443");err!=nil{t.Fatal(err)}
	b.Close()
	if _,err=peer.Read(p);err==nil{t.Fatal("broker close left upstream open")}
	if _,err=b.Open(context.Background(),x,"route.netverge.test:443");err==nil{t.Fatal("closed broker admitted lease")}
}

func TestBrokerExpiryAndCancellation(t *testing.T){
	b,err:=NewBroker(2,100*time.Millisecond,time.Second)
	if err!=nil{t.Fatal(err)}
	defer b.Close()
	a,z:=net.Pipe()
	defer z.Close()
	if _,err=b.Open(context.Background(),a,"route.netverge.test:443");err!=nil{t.Fatal(err)}
	_=z.SetReadDeadline(time.Now().Add(3*time.Second))
	if _,err=z.Read(make([]byte,1));err==nil{t.Fatal("expired lease retained stream")}else if ne,ok:=err.(net.Error);ok&&ne.Timeout(){t.Fatal("expiry did not close stream")}
	ctx,cancel:=context.WithCancel(context.Background())
	c,d:=net.Pipe()
	defer d.Close()
	if _,err=b.Open(ctx,c,"route.netverge.test:443");err!=nil{t.Fatal(err)}
	cancel()
	_=d.SetReadDeadline(time.Now().Add(3*time.Second))
	if _,err=d.Read(make([]byte,1));err==nil{t.Fatal("cancel retained stream")}else if ne,ok:=err.(net.Error);ok&&ne.Timeout(){t.Fatal("cancel did not close stream")}
}
