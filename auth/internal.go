package auth

import (
	"github.com/rgooding/authproxy/config"
	"net/http"
)

type InternalAuthenticator struct {
	userList map[string]*config.InternalUser
}

func NewInternalAuthenticator(users []*config.InternalUser) *InternalAuthenticator {
	userList := make(map[string]*config.InternalUser)
	for _, user := range users {
		userList[user.Username] = user
	}
	return &InternalAuthenticator{
		userList: userList,
	}
}

func (a InternalAuthenticator) AuthRequest(r *http.Request, host *config.HostConfig) (string, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", ErrNoAuth
	}
	user, ok := a.userList[username]
	if !ok || password != user.Password {
		return "", ErrBadPassword
	}

	// User authenticated successfully. Are they allowed access?
	groupMap := make(map[string]bool)
	// Only get the groups from LDAP if we need them on this request
	if len(host.AllowGroups) > 0 || len(host.DenyGroups) > 0 {
		// Put groups in a map to speed up the check
		for _, g := range user.Groups {
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

	// Authentication successful
	return username, nil
}
