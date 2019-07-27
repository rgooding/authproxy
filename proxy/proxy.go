package proxy

import (
	"fmt"
	"github.com/rgooding/authproxy/auth"
	"github.com/rgooding/authproxy/config"
	"github.com/rgooding/authproxy/types"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
)

type Proxy struct {
	P              *httputil.ReverseProxy
	cfg            *config.Config
	authenticators []auth.Authenticator
}

func logRequest(r *http.Request, msg string, a ...interface{}) {
	var fullMsg string
	if len(a) > 0 {
		fullMsg = fmt.Sprintf(msg, a...)
	} else {
		fullMsg = msg
	}

	var scheme string
	if r.TLS == nil {
		scheme = "http"
	} else {
		scheme = "https"
	}
	log.Printf("%s %s %s://%s%s %s", r.RemoteAddr, r.Method, scheme, r.Host, r.RequestURI, fullMsg)
}

func NewProxy(cfg *config.Config) *Proxy {
	auths := []auth.Authenticator{
		auth.NewInternalAuthenticator(cfg.InternalUsers),
	}
	for _, lc := range cfg.LdapServers {
		auths = append(auths, auth.NewLdapAuthenticator(lc))
	}

	p := &Proxy{
		cfg:            cfg,
		authenticators: auths,
	}
	p.P = &httputil.ReverseProxy{
		Director: p.Director,
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if hostCfg, found := p.hostForRequest(r); found {
		username, password, ok := r.BasicAuth()
		if !ok {
			logRequest(r, "invalid or missing credentials")
			w.Header().Set("WWW-Authenticate", `Basic realm="`+hostCfg.AuthRealm+`"`)
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
			return
		}

		ok, err := p.authRequest(username, password, hostCfg)
		if err != nil {
			if err == auth.ErrNoAuth {
				logRequest(r, err.Error())
			} else {
				logRequest(r, "ERROR: user '%s': %s", username, err.Error())
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="`+hostCfg.AuthRealm+`"`)
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
			return
		}

		// All good, forward the request
		logRequest(r, "=> %s (user=%s)", hostCfg.Upstream, username)
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

func (p *Proxy) authRequest(username, password string, hostCfg *config.HostConfig) (bool, error) {
	var passOk bool
	var authenticator auth.Authenticator
	for _, a := range p.authenticators {
		ok, err := a.CheckPassword(username, password)
		if ok && err == nil {
			passOk = true
			authenticator = a
			break
		}
	}

	if !passOk {
		return false, auth.ErrBadPassword
	}

	// Check access rules
	allowed, err := p.checkAccess(username, hostCfg, authenticator)
	if err != nil {
		return false, err
	}
	if !allowed {
		return false, auth.ErrAccessDenied
	}
	return true, nil
}

func (p *Proxy) checkAccess(username string, hostCfg *config.HostConfig, authenticator auth.Authenticator) (bool, error) {
	// Check DenyUsers first
	for _, user := range hostCfg.DenyUsers {
		if username == user {
			return false, nil
		}
	}

	// Only load groups if required
	var groups *types.StringSet
	if len(hostCfg.AllowGroups) > 0 || len(hostCfg.DenyGroups) > 0 {
		var err error
		groups, err = authenticator.GetGroups(username)
		if err != nil {
			return false, err
		}
	}

	// Check DenyGroups
	if groups.ContainsOne(hostCfg.DenyGroups) {
		return false, nil
	}

	// Allow by default if AllowAll is set
	allowed := hostCfg.AllowAll

	// Check AllowUsers
	if !allowed {
		for _, user := range hostCfg.AllowUsers {
			if user == username {
				allowed = true
				break
			}
		}
	}

	// Check AllowGroups
	if !allowed {
		allowed = groups.ContainsOne(hostCfg.AllowGroups)
	}

	return allowed, nil
}
