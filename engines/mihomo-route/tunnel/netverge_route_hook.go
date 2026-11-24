// NetVerge's internal, opt-in original-route handoff boundary.
// No listener, remote configuration, automatic trust or desktop activation.
package tunnel

import (
	"errors"
	"net"
	"strings"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

// NetVergeRouteHandler runs synchronously on the original TCP connection.
// The tunnel retains responsibility for closing both streams. Once admitted,
// a handler failure terminates the flow; it never invokes the native retry.
type NetVergeRouteHandler func(client net.Conn, upstream C.Conn, metadata *C.Metadata, rule C.Rule) error

type netVergeRouteConfig struct {
	hosts map[string]struct{}
	handle NetVergeRouteHandler
}

var netVergeRouteState struct {
	sync.RWMutex
	config *netVergeRouteConfig
}

// SetNetVergeRouteHandler is an internal Go-only seam for a future trusted
// local controller. Nil disables new handoffs. No external API calls this yet.
// Existing admitted streams remain owned by the handler until it returns.
func SetNetVergeRouteHandler(hosts []string, handler NetVergeRouteHandler) error {
	var next *netVergeRouteConfig
	if handler != nil {
		if len(hosts)==0 || len(hosts)>64 {return errors.New("invalid MITM host count")}
		next=&netVergeRouteConfig{hosts:make(map[string]struct{},len(hosts)),handle:handler}
		for _,host:=range hosts {
			if len(host)>253 || !strings.Contains(host,".") || net.ParseIP(host)!=nil {return errors.New("invalid MITM host")}
			for _,label:=range strings.Split(host,".") {
				if len(label)==0 || len(label)>63 || label[0]=='-' || label[len(label)-1]=='-' {return errors.New("invalid MITM host")}
				for _,c:=range label {if !(c>='a'&&c<='z'||c>='0'&&c<='9'||c=='-'){return errors.New("invalid MITM host")}}
			}
			next.hosts[host]=struct{}{}
		}
	}
	netVergeRouteState.Lock()
	netVergeRouteState.config=next
	netVergeRouteState.Unlock()
	return nil
}

func netVergeRouteCandidate(m *C.Metadata) *netVergeRouteConfig {
	if m.Type!=C.TUN || m.NetWork!=C.TCP || m.DstPort!=443 || Mode()!=Rule || m.SpecialProxy!="" {return nil}
	netVergeRouteState.RLock()
	defer netVergeRouteState.RUnlock()
	cfg:=netVergeRouteState.config
	if cfg==nil {return nil}
	if _,ok:=cfg.hosts[m.Host];!ok{return nil}
	return cfg
}

type netVergeAdapterTrace interface { NetVergeLabAdapterTypes() []C.AdapterType }

// Start narrowly with actual eager DIRECT/HTTP and lazy VLESS. The latter
// is a controlled integration gate, not a claim of all transport variants.
// Never infer rejection from a display name or unwrap to choose a new route.
func netVergeRouteAdmit(proxy C.Proxy, conn C.Conn) bool {
	if proxy==nil || conn==nil{return false}
	trace,ok:=N.FindUpstream[netVergeAdapterTrace](conn,nil)
	if !ok{return false}
	types:=trace.NetVergeLabAdapterTypes()
	if len(types)==0 || len(types)!=len(conn.Chains()) || types[len(types)-1]!=proxy.Type(){return false}
	switch types[0] {
	case C.Direct,C.Http:
		if N.NeedHandshake(conn){return false}
	case C.Vless:
		if !N.NeedHandshake(conn){return false}
	default:return false
	}
	for _,typ:=range types[1:] {
		switch typ {case C.Selector,C.URLTest,C.Fallback,C.LoadBalance:default:return false}
	}
	return true
}
