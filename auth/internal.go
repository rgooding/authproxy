package auth

import (
	"github.com/rgooding/authproxy/config"
	"github.com/rgooding/authproxy/types"
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

func (a *InternalAuthenticator) CheckPassword(username, password string) (bool, error) {
	if user, ok := a.userList[username]; ok {
		if ComparePasswordAndHash(password, user.Password) {
			return true, nil
		}
		return false, ErrBadPassword
	}
	return false, ErrUserNotFound
}

func (a *InternalAuthenticator) GetGroups(username string) (*types.StringSet, error) {
	if user, ok := a.userList[username]; ok {
		return types.NewSetFromList(user.Groups), nil
	}
	return nil, ErrUserNotFound
}
