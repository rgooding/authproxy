// Imported from https://github.com/jtblin/go-ldap-client

// Package ldap provides a simple ldap client to authenticate,
// retrieve basic information and groups for a user.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"gopkg.in/ldap.v2"
)

type LDAPClient struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	ServerName         string
	UserFilter         string // e.g. "(uid=%s)"
	Conn               *ldap.Conn
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate // Adding client certificates
	CallAttempts       int
	mu                 sync.Mutex
}

// connect connects to the ldap backend.
func (lc *LDAPClient) connect() error {
	if lc.Conn == nil {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return err
				}
			}
		} else {
			config := &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify,
				ServerName:         lc.ServerName,
			}
			if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
				config.Certificates = lc.ClientCertificates
			}
			l, err = ldap.DialTLS("tcp", address, config)
			if err != nil {
				return err
			}
		}

		lc.Conn = l
	}
	return nil
}

// Close closes the ldap backend connection.
func (lc *LDAPClient) Close() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.close()
}

func (lc *LDAPClient) close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

func (lc *LDAPClient) reconnectIfNetworkError(err error, attempt int) bool {
	if lErr, ok := err.(*ldap.Error); ok && lErr.ResultCode == ldap.ErrorNetwork {
		// disconnect for the next attempt
		lc.close()
		// exponential backoff
		time.Sleep(time.Duration(attempt) * 50 * time.Millisecond)
		return true
	}
	return false
}

func (lc *LDAPClient) bindWithRetries(bindDN, bindPassword string) error {
	var err error
	for i := 1; i <= lc.CallAttempts; i++ {
		err = lc.connect()
		if err == nil {
			err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		}
		// Check for network errors and reconnect
		if !lc.reconnectIfNetworkError(err, i) {
			return err
		}
	}
	return err
}

func (lc *LDAPClient) searchWithRetries(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	var err error
	for i := 1; i <= lc.CallAttempts; i++ {
		var sr *ldap.SearchResult
		err = lc.connect()
		if err == nil {
			sr, err = lc.Conn.Search(searchRequest)
		}

		// Check for network errors and reconnect
		if !lc.reconnectIfNetworkError(err, i) {
			return sr, err
		}
	}
	return nil, err
}

// Authenticate authenticates the user against the ldap backend.
func (lc *LDAPClient) Authenticate(username, password string) (bool, map[string]string, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.bindWithRetries(lc.BindDN, lc.BindPassword)
		if err != nil {
			return false, nil, err
		}
	}

	attributes := append(lc.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	sr, err := lc.searchWithRetries(searchRequest)
	if err != nil {
		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		return false, nil, errors.New("user does not exist")
	}

	if len(sr.Entries) > 1 {
		return false, nil, errors.New("too many entries returned")
	}

	userDN := sr.Entries[0].DN
	user := map[string]string{}
	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	err = lc.bindWithRetries(userDN, password)
	if err != nil {
		return false, user, err
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.bindWithRetries(lc.BindDN, lc.BindPassword)
		if err != nil {
			return true, user, err
		}
	}

	return true, user, nil
}

// GetGroupsOfUser returns the group for a user.
func (lc *LDAPClient) GetGroupsOfUser(username string) ([]string, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.GroupFilter, username),
		[]string{"cn"}, // can it be something else than "cn"?
		nil,
	)
	sr, err := lc.searchWithRetries(searchRequest)
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}
