package auth

import (
	"crypto/md5"
	"sync"
	"time"
)

type Cache struct {
	ttl       time.Duration
	creds     map[string][16]byte
	credsExp  map[string]time.Time
	groups    map[string]map[string]bool
	groupsExp map[string]time.Time
	mu        sync.RWMutex
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		ttl:       ttl,
		creds:     make(map[string][16]byte),
		credsExp:  make(map[string]time.Time),
		groups:    make(map[string]map[string]bool),
		groupsExp: make(map[string]time.Time),
	}
}

func (c *Cache) AddCreds(username, password string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.creds[username] = md5.Sum([]byte(password))
	c.credsExp[username] = time.Now().Add(c.ttl)
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
		if h, ok := c.creds[username]; ok && h == md5.Sum([]byte(password)) {
			return true
		}
	}
	return false
}

func (c *Cache) AddGroups(username string, groupMap map[string]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.groups[username] = groupMap
	c.groupsExp[username] = time.Now().Add(c.ttl)
}

func (c *Cache) GetGroups(username string) (map[string]bool, bool) {
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
