package proxy

import (
	"fmt"
	"github.com/rgooding/http-ldap-auth-proxy/auth"
	"github.com/rgooding/http-ldap-auth-proxy/config"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
)

type Proxy struct {
	P   *httputil.ReverseProxy
	cfg *config.Config
}

func logRequest(r *http.Request, msg string) {
	log.Printf("%s %s%s %s", r.Method, r.Host, r.RequestURI, msg)
}

func NewProxy(cfg *config.Config) *Proxy {
	p := &Proxy{
		cfg: cfg,
	}
	p.P = &httputil.ReverseProxy{
		Director: p.Director,
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if hostCfg, found := p.hostForRequest(r); found {
		if user, ok := auth.AuthRequest(r, hostCfg); ok {
			// All good, forward the request
			logRequest(r, fmt.Sprintf("=> %s (user=%s)", hostCfg.Upstream, user))
			p.P.ServeHTTP(w, r)
		} else {
			logRequest(r, "authentication failed (user=%s)")

			var realm string
			if hostCfg.AuthRealm != "" {
				realm = hostCfg.AuthRealm
			} else {
				realm = hostCfg.AuthRealm
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)

			http.Error(w, "Authentication failed", http.StatusUnauthorized)
		}
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
