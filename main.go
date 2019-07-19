package main

import (
	"github.com/rgooding/http-ldap-auth-proxy/config"
	"log"
)

var cfg *config.Config

func startProxy(host config.HostConfig) error {
	// TODO
	return nil
}

func main() {
	var err error
	cfg,err = config.Load("config.yaml")
	if err != nil{
		log.Fatalf("Error loading config file: %s", err.Error())
	}

	// start proxy servers
	for _, host := range cfg.Hosts {
		err := startProxy(host)
		if err != nil {
			log.Fatal(err)
		}
	}
}
