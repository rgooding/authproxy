package auth

import (
	"errors"
	"github.com/rgooding/http-ldap-auth-proxy/config"
	"net/http"
)

var ErrNoAuth = errors.New("invalid or missing credentials")
var ErrUnknown = errors.New("unknown error")

type Authenticator interface {
	AuthRequest(r *http.Request, host *config.HostConfig) (string, error)
}
