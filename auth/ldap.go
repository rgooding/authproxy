package auth

import (
	"github.com/jtblin/go-ldap-client"
	"github.com/rgooding/http-ldap-auth-proxy/config"
	"net/http"
)

type LdapAuthenticator struct {
	client *ldap.LDAPClient
}

func NewLdapAuthenticator(cfg *config.Config) *LdapAuthenticator {
	return &LdapAuthenticator{
		client: &ldap.LDAPClient{
			Base:         cfg.Ldap.Base,
			Host:         cfg.Ldap.Host,
			Port:         cfg.Ldap.Port,
			UseSSL:       cfg.Ldap.SSL,
			SkipTLS:      !cfg.Ldap.StartTLS,
			BindDN:       cfg.Ldap.BindDn,
			BindPassword: cfg.Ldap.BindPw,
			UserFilter:   cfg.Ldap.UserFilter,
			GroupFilter:  cfg.Ldap.GroupFilter,
		},
	}
}

func (a *LdapAuthenticator) AuthRequest(r *http.Request, host *config.HostConfig) (string, error) {
	if username, password, ok := r.BasicAuth(); ok {
		ok, _, err := a.client.Authenticate(username, password)
		if !ok || err != nil {
			if err == nil {
				err = ErrUnknown
			}
			return username, err
		}
		return username, nil
	}
	return "", ErrNoAuth
}
