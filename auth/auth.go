package auth

import (
	"github.com/rgooding/http-ldap-auth-proxy/config"
	"net/http"
)

func AuthRequest(r *http.Request, host *config.HostConfig) (string, bool) {
	// TODO: Check if this request is authenticated
	if username, password, ok := r.BasicAuth(); ok {
		if username == "test" && password == "test" {
			return username, true
		}
	}
	return "", false
}
