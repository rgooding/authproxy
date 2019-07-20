package auth

import (
	"errors"
	"github.com/rgooding/authproxy/config"
	"net/http"
)

var ErrNoAuth = errors.New("invalid or missing credentials")
var ErrUnknown = errors.New("unknown error")
var ErrAccessDenied = errors.New("access denied by configuration")

type Authenticator interface {
	AuthRequest(r *http.Request, host *config.HostConfig) (string, error)
}
