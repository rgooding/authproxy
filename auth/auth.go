package auth

import (
	"errors"
	"github.com/rgooding/authproxy/types"
	"golang.org/x/crypto/bcrypt"
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

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func ComparePasswordAndHash(password, hash string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return false
	}
	return true
}
