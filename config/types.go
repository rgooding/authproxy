package config

type LdapConfig struct {
	Server string `yaml:"server"`
	BindDn string `yaml:"bind_dn"`
	BindPw string `yaml:"bind_pw"`
}

type TlsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Cert    string `yaml:"cert"`
	Chain   string `yaml:"chain"`
	Key     string `yaml:"key"`
}

type HostConfig struct {
	Hostname string `yaml:"hostname"`
	Upstream string `yaml:"upstream"`

	AllowGroups []string `yaml:"allow_groups"`
	AllowUsers  []string `yaml:"allow_users"`
	DenyGroups  []string `yaml:"deny_groups"`
	DenyUsers   []string `yaml:"deny_users"`

	HttpPort      int  `yaml:"http_port"`
	HttpsPort     int  `yaml:"https_port"`
	HttpsRedirect bool `yaml:"https_redirect"`

	Ldap LdapConfig `yaml:"ldap"`
	Tls  TlsConfig  `yaml:"tls"`
}

type Config struct {
	HttpPort      int  `yaml:"http_port"`
	HttpsPort     int  `yaml:"https_port"`
	HttpsRedirect bool `yaml:"https_redirect"`

	Ldap LdapConfig `yaml:"ldap"`
	Tls  TlsConfig  `yaml:"tls"`

	Hosts []HostConfig `yaml:"hosts"`
}
