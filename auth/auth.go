package auth

import (
	"github.com/rgooding/http-ldap-auth-proxy/config"
	"net/http"
)

func AuthRequest(r *http.Request, host *config.HostConfig) (string, bool) {
	// TODO: Check if this request is authenticated
	return "username", true
}
