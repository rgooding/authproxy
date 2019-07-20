package auth

import (
	"errors"
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

		// User authenticated successfully. Are they allowed access?
		allowed := host.AllowAll
		// Check if the user is in the list of allowed users
		if !allowed {
			for _, user := range host.AllowUsers {
				if user == username {
					allowed = true
					break
				}
			}
		}
		// Check if the user is in one of the allowed groups
		if !allowed && len(host.AllowGroups) > 0 {
			groups, err := a.client.GetGroupsOfUser(username)
			if err != nil {
				return username, err
			}
			// Put groups in a map to speed up the check
			groupMap := make(map[string]bool)
			for _, g := range groups {
				groupMap[g] = true
			}
			for _, ag := range host.AllowGroups {
				if _, ok := groupMap[ag]; ok {
					allowed = true
					break
				}
			}
		}

		if !allowed {
			return username, errors.New("access denied by configuration")
		}

		return username, nil
	}
	return "", ErrNoAuth
}
