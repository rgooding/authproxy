package config

import "net/url"

type InternalUser struct {
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	Groups   []string `yaml:"groups"`
}

type LdapConfig struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	SSL          bool   `yaml:"ssl"`
	StartTLS     bool   `yaml:"starttls"`
	Base         string `yaml:"base"`
	BindDn       string `yaml:"bind_dn"`
	BindPw       string `yaml:"bind_pw"`
	UserFilter   string `yaml:"user_filter"`
	GroupFilter  string `yaml:"group_filter"`
	CacheSeconds int    `yaml:"cache_seconds"`
	CallAttempts int    `yaml:"call_attempts"`
}

type TlsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Cert    string `yaml:"cert"`
	Chain   string `yaml:"chain"`
	Key     string `yaml:"key"`
}

type HostConfig struct {
	Hostnames    []string `yaml:"hostnames"`
	Upstream     string   `yaml:"upstream"`
	UpstreamUrl  *url.URL
	PreserveHost bool `yaml:"preserve_host"`

	AuthRealm   string   `yaml:"auth_realm"`
	AllowAll    bool     `yaml:"allow_all"`
	AllowGroups []string `yaml:"allow_groups"`
	AllowUsers  []string `yaml:"allow_users"`
	DenyGroups  []string `yaml:"deny_groups"`
	DenyUsers   []string `yaml:"deny_users"`
}

type Config struct {
	ListenAddress string `yaml:"listen_address"`
	HttpPort      int    `yaml:"http_port"`
	HttpsPort     int    `yaml:"https_port"`
	HttpsRedirect bool   `yaml:"https_redirect"`

	AuthRealm     string          `yaml:"auth_realm"`
	LdapServers   []*LdapConfig   `yaml:"ldap_servers"`
	InternalUsers []*InternalUser `yaml:"internal_users"`
	Tls           TlsConfig       `yaml:"tls"`

	Hosts []*HostConfig `yaml:"hosts"`
}
