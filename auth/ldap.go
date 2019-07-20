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

		// User authenticated successfully. Are they allowed access?

		// Get user groups from LDAP if required
		groupMap := make(map[string]bool)
		if len(host.AllowGroups) > 0 || len(host.DenyGroups) > 0 {
			userGroups, err := a.client.GetGroupsOfUser(username)
			if err != nil {
				return username, err
			}
			// Put groups in a map to speed up the check
			for _, g := range userGroups {
				groupMap[g] = true
			}
		}

		// Check DenyUsers first
		for _, user := range host.DenyUsers {
			if username == user {
				return username, ErrAccessDenied
			}
		}

		// Check DenyGroups
		for _, dg := range host.DenyGroups {
			if _, ok := groupMap[dg]; ok {
				return username, ErrAccessDenied
			}
		}

		// Check Allow rules
		allowed := host.AllowAll
		// Check AllowUsers
		if !allowed {
			for _, user := range host.AllowUsers {
				if user == username {
					allowed = true
					break
				}
			}
		}

		// Check AllowGroups
		if !allowed && len(host.AllowGroups) > 0 {
			for _, ag := range host.AllowGroups {
				if _, ok := groupMap[ag]; ok {
					allowed = true
					break
				}
			}
		}

		if !allowed {
			return username, ErrAccessDenied
		}

		return username, nil
	}
	return "", ErrNoAuth
}
