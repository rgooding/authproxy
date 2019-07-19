package main

import (
	"fmt"
	"github.com/rgooding/http-ldap-auth-proxy/config"
	"github.com/rgooding/http-ldap-auth-proxy/proxy"
	"log"
	"net/http"
	"sync"
)

func main() {
	var err error
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config file: %s", err.Error())
	}

	p := proxy.NewProxy(cfg)

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
