//go:build windows && netverge_service_lab

package route

// Isolated laboratory only. The regular build does not install this file
// or patch server.go. No actual service or watchdog activation is enabled.
import (
 "crypto/subtle"
 "encoding/base64"
 "encoding/json"
 "io"
 "os"
 "regexp"
 "sync"
 "strings"
 "sync/atomic"

 "github.com/metacubex/http"
 "github.com/metacubex/mihomo/netvergecontrol"
 "github.com/metacubex/mihomo/tunnel"
)

const nvBootstrapPath="/__netverge_service_lab/bootstrap"
var nvOwnerACL=regexp.MustCompile(`^D:P\(A;;GA;;;S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\)\(A;;GA;;;SY\)\(A;;GA;;;BA\)$`)
var nvEnvLaunch=func() bool {
 _,p:=os.LookupEnv("NETVERGE_CORE_CONTROL_PORT")
 _,s:=os.LookupEnv("NETVERGE_CORE_CONTROL_SECRET")
 return p||s
}()
var nvLabArmed atomic.Bool

// Called only by the isolated lab executable, before hub.Parse.
func NetVergeServiceLabArm(pipe string){
 if nvEnvLaunch||!nvOwnerACL.MatchString(os.Getenv("LISTEN_NAMEDPIPE_SDDL"))||!strings.HasPrefix(pipe,`\\.\pipe\`){return}
 tunnel.SetNetVergeStartupFence(true)
 nvLabArmed.Store(true)
}

var nvBootstrap struct {
 sync.Mutex
 controller *netvergecontrol.Controller
 port int
 secret string
}
type nvBootstrapInput struct {
 Port int `json:"port"`
 Secret string `json:"secret"`
}
func netvergeServicePipeHandler(next http.Handler) http.Handler {
 if !nvLabArmed.Load()||nvEnvLaunch||!nvOwnerACL.MatchString(os.Getenv("LISTEN_NAMEDPIPE_SDDL")){return next}
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path!=nvBootstrapPath{next.ServeHTTP(w,r);return}
  w.Header().Set("Cache-Control","no-store")
  w.Header().Set("Connection","close")
  if r.Host!="netverge-local"||r.URL.RawQuery!=""||r.Header.Get("Origin")!=""{w.WriteHeader(403);return}
  if r.Method!="POST"{w.WriteHeader(405);return}
  if r.Header.Get("Content-Type")!="application/json"||r.ContentLength<1||r.ContentLength>1024||len(r.TransferEncoding)!=0{w.WriteHeader(400);return}
  var input nvBootstrapInput
  dec:=json.NewDecoder(io.LimitReader(r.Body,1025))
  dec.DisallowUnknownFields()
  if dec.Decode(&input)!=nil||dec.Decode(new(any))!=io.EOF||input.Port<1024||input.Port>65535||len(input.Secret)!=32{w.WriteHeader(400);return}
  b,err:=base64.RawURLEncoding.DecodeString(input.Secret)
  if err!=nil||len(b)!=24{w.WriteHeader(400);return}
  nvBootstrap.Lock()
  defer nvBootstrap.Unlock()
  if nvBootstrap.controller!=nil{
   if nvBootstrap.port==input.Port&&subtle.ConstantTimeCompare([]byte(nvBootstrap.secret),[]byte(input.Secret))==1{w.WriteHeader(204)}else{w.WriteHeader(409)}
   return
  }
  controller,err:=netvergecontrol.StartGuarded(input.Port,input.Secret)
  if err!=nil{w.WriteHeader(503);return}
  nvBootstrap.controller=controller
  nvBootstrap.port=input.Port
  nvBootstrap.secret=input.Secret
  w.WriteHeader(204)
 })
}
