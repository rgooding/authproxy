package proxy

import (
	"fmt"
	"github.com/rgooding/authproxy/auth"
	"github.com/rgooding/authproxy/config"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
)

type Proxy struct {
	P    *httputil.ReverseProxy
	cfg  *config.Config
	auth auth.Authenticator
}

func logRequest(r *http.Request, msg string, a ...interface{}) {
	var fullMsg string
	if len(a) > 0 {
		fullMsg = fmt.Sprintf(msg, a...)
	} else {
		fullMsg = msg
	}
	log.Printf("%s %s %s%s %s", r.RemoteAddr, r.Method, r.Host, r.RequestURI, fullMsg)
}

func NewProxy(cfg *config.Config, a auth.Authenticator) *Proxy {
	p := &Proxy{
		cfg:  cfg,
		auth: a,
	}
	p.P = &httputil.ReverseProxy{
		Director: p.Director,
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if hostCfg, found := p.hostForRequest(r); found {

		user, err := p.auth.AuthRequest(r, hostCfg)
		if err != nil {
			if err == auth.ErrNoAuth {
				logRequest(r, err.Error())
			} else {
				logRequest(r, "ERROR: user '%s': %s", user, err.Error())
			}

			realm := hostCfg.AuthRealm
			if realm == "" {
				realm = config.DefaultAuthRealm
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
			return
		}

		// All good, forward the request
		logRequest(r, "=> %s (user=%s)", hostCfg.Upstream, user)
		p.P.ServeHTTP(w, r)
	} else {
		logRequest(r, "no upstream configured for request")
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

func (p *Proxy) Director(r *http.Request) {
	if host, found := p.hostForRequest(r); found {
		r.URL.Scheme = host.UpstreamUrl.Scheme
		r.URL.Host = host.UpstreamUrl.Host
		//r.Host = host.UpstreamUrl.Host
		r.Header.Add("X-Forwarded-Host", r.Host)
		r.Header.Add("X-Origin-Host", host.UpstreamUrl.Host)
	}
}

func (p *Proxy) hostForRequest(r *http.Request) (*config.HostConfig, bool) {
	reqHost := strings.ToLower(r.Host)
	for _, host := range p.cfg.Hosts {
		for _, hostname := range host.Hostnames {
			if reqHost == strings.ToLower(hostname) {
				return host, true
			}
		}
	}
	return nil, false
}
