package auth

import (
	"github.com/rgooding/authproxy/types"
	"log"
	"sync"
	"time"
)

type Cache struct {
	ttl       time.Duration
	creds     map[string]string
	credsExp  map[string]time.Time
	groups    map[string]*types.StringSet
	groupsExp map[string]time.Time
	mu        sync.RWMutex
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		ttl:       ttl,
		creds:     make(map[string]string),
		credsExp:  make(map[string]time.Time),
		groups:    make(map[string]*types.StringSet),
		groupsExp: make(map[string]time.Time),
	}
}

func (c *Cache) AddCreds(username, password string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h, err := HashPassword(password)
	if err != nil {
		log.Printf("Error hashing password: %s", err.Error())
	} else {
		c.creds[username] = h
		c.credsExp[username] = time.Now().Add(c.ttl)
	}
}

func (c *Cache) Drop(username string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.creds, username)
	delete(c.credsExp, username)
	delete(c.groups, username)
	delete(c.groupsExp, username)
}

func (c *Cache) CheckCreds(username, password string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if exp, ok := c.credsExp[username]; ok {
		if exp.Before(time.Now()) {
			return false
		}
		if h, ok := c.creds[username]; ok {
			return ComparePasswordAndHash(password, h)
		}
	}
	return false
}

func (c *Cache) AddGroups(username string, groups *types.StringSet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.groups[username] = groups
	c.groupsExp[username] = time.Now().Add(c.ttl)
}

func (c *Cache) GetGroups(username string) (*types.StringSet, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if exp, ok := c.groupsExp[username]; ok {
		if exp.Before(time.Now()) {
			return nil, false
		}
		groups, ok := c.groups[username]
		return groups, ok
	}
	return nil, false
}
