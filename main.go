package main

import (
	"fmt"
	"github.com/rgooding/authproxy/auth"
	"github.com/rgooding/authproxy/config"
	"github.com/rgooding/authproxy/proxy"
	"log"
	"net/http"
	"os"
	"sync"
)

const configFile = "config.yaml"
const localConfigFile = "config.local.yaml"

func main() {
	var err error
	var cfg *config.Config
	if _, err = os.Stat(localConfigFile); err == nil {
		cfg, err = config.Load(localConfigFile)
	} else {
		cfg, err = config.Load(configFile)
	}
	if err != nil {
		log.Fatalf("Error loading config file: %s", err.Error())
	}

	p := proxy.NewProxy(cfg, auth.NewLdapAuthenticator(cfg))

	var wg sync.WaitGroup
	if cfg.HttpPort > 0 {
		wg.Add(1)
		go func() {
			log.Printf("HTTP proxy listening on %s:%d", cfg.ListenAddress, cfg.HttpPort)
			addr := fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.HttpPort)
			log.Fatal(http.ListenAndServe(addr, p))
		}()
	}
	if cfg.HttpsPort > 0 {
		wg.Add(1)
		go func() {
			log.Printf("HTTPS proxy listening on %s:%d", cfg.ListenAddress, cfg.HttpsPort)
			addr := fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.HttpsPort)
			log.Fatal(http.ListenAndServeTLS(addr, cfg.Tls.Cert, cfg.Tls.Key, p))
		}()
	}
	wg.Wait()
}
