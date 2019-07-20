package config

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/url"
)

const DefaultAuthRealm = "login"

func Load(configFile string) (*Config, error) {
	var config Config

	log.Printf("Loading config from %s\n", configFile)

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	// Set default values
	if config.AuthRealm == "" {
		config.AuthRealm = DefaultAuthRealm
	}
	if config.Ldap.UserFilter == "" {
		config.Ldap.UserFilter = "(uid=%s)"
	}
	if config.Ldap.GroupFilter == "" {
		config.Ldap.GroupFilter = "(memberUid=%s)"
	}

	// Parse upstream URLs
	for _, host := range config.Hosts {
		u, err := url.Parse(host.Upstream)
		if err != nil {
			return nil, fmt.Errorf("error parsing upstream URL %s : %s", host.Upstream, err.Error())
		}
		host.UpstreamUrl = u
	}

	return &config, nil
}
