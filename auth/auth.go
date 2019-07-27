package auth

import (
	"errors"
	"github.com/rgooding/authproxy/types"
)

var ErrNoAuth = errors.New("invalid or missing credentials")
var ErrUnknown = errors.New("unknown error")
var ErrAccessDenied = errors.New("access denied by configuration")
var ErrUserNotFound = errors.New("user not found")
var ErrBadPassword = errors.New("incorrect username or password")

type Authenticator interface {
	CheckPassword(username, password string) (bool, error)
	GetGroups(username string) (*types.StringSet, error)
}
