package config

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

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

	// TODO: Validate the config

	return &config, nil
}
