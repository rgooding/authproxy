package auth

import (
	"github.com/rgooding/authproxy/config"
	"github.com/rgooding/authproxy/ldap"
	"github.com/rgooding/authproxy/types"
	"time"
)

type LdapAuthenticator struct {
	client *ldap.LDAPClient
	cache  *Cache
}

func NewLdapAuthenticator(cfg *config.LdapConfig) *LdapAuthenticator {
	return &LdapAuthenticator{
		client: &ldap.LDAPClient{
			Base:         cfg.Base,
			Host:         cfg.Host,
			ServerName:   cfg.Host,
			Port:         cfg.Port,
			UseSSL:       cfg.SSL,
			StartTLS:     cfg.StartTLS,
			BindDN:       cfg.BindDn,
			BindPassword: cfg.BindPw,
			UserFilter:   cfg.UserFilter,
			GroupFilter:  cfg.GroupFilter,
			CallAttempts: cfg.CallAttempts,
		},
		cache: NewCache(time.Duration(cfg.CacheSeconds) * time.Second),
	}
}

func (a *LdapAuthenticator) CheckPassword(username, password string) (bool, error) {
	if a.cache.CheckCreds(username, password) {
		return true, nil
	}

	// Cached auth failed, try LDAP
	ok, _, err := a.client.Authenticate(username, password)
	if !ok || err != nil {
		if err == nil {
			err = ErrUnknown
		}
		// drop cache on auth failure
		a.cache.Drop(username)
		return false, err
	}

	// LDAP auth successful. Cache the result
	a.cache.AddCreds(username, password)
	return true, nil
}

func (a *LdapAuthenticator) GetGroups(username string) (*types.StringSet, error) {
	if groups, ok := a.cache.GetGroups(username); ok {
		return groups, nil
	}

	ldapGroups, err := a.client.GetGroupsOfUser(username)
	if err != nil {
		return nil, err
	}

	// Group lookup successful. Cache the result
	groups := types.NewSetFromList(ldapGroups)
	a.cache.AddGroups(username, groups)
	return groups, nil
}
