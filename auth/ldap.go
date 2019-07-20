package auth

import (
	"github.com/jtblin/go-ldap-client"
	"github.com/rgooding/http-ldap-auth-proxy/config"
	"net/http"
	"time"
)

type LdapAuthenticator struct {
	client *ldap.LDAPClient
	cache  *Cache
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
		cache: NewCache(time.Duration(cfg.Ldap.CacheSeconds) * time.Second),
	}
}

func (a *LdapAuthenticator) AuthRequest(r *http.Request, host *config.HostConfig) (string, error) {
	if username, password, ok := r.BasicAuth(); ok {
		// Authenticate the user
		if ! a.cache.CheckCreds(username, password) {
			// Cached auth failed, try LDAP
			ok, _, err := a.client.Authenticate(username, password)
			if !ok || err != nil {
				if err == nil {
					err = ErrUnknown
				}
				// drop cache on auth failure
				a.cache.Drop(username)
				return username, err
			}
		}

		// User authenticated successfully. Are they allowed access?

		// Get user groups from LDAP if required
		var groupMap map[string]bool

		groupMap, ok := a.cache.GetGroups(username)
		if !ok {
			groupMap = make(map[string]bool)
			// Only get the groups from LDAP if we need them on this request
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
				// Drop cache on group denied in case of changes
				a.cache.Drop(username)
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
			if !allowed {
				// Drop cache on group denied in case of changes
				a.cache.Drop(username)
			}
		}

		if !allowed {
			return username, ErrAccessDenied
		}

		// Authentication successful. Cache the results
		a.cache.AddCreds(username, password)
		if groupMap != nil && len(groupMap) > 0 {
			a.cache.AddGroups(username, groupMap)
		}

		return username, nil
	}
	return "", ErrNoAuth
}
