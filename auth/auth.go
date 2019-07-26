package auth

import (
	"errors"
	"github.com/rgooding/authproxy/config"
	"net/http"
)

var ErrNoAuth = errors.New("invalid or missing credentials")
var ErrUnknown = errors.New("unknown error")
var ErrAccessDenied = errors.New("access denied by configuration")
var ErrBadPassword = errors.New("incorrect username or password")
var ErrAuthFailed = errors.New("authentication failed")

type Authenticator interface {
	AuthRequest(r *http.Request, host *config.HostConfig) (string, error)
}
