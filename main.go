package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"

	"github.com/rgooding/http-ldap-auth-proxy/config"
)

var cfg *config.Config

func director(req *http.Request) {
	var hostForReq *config.HostConfig

	// Find the upstream config for this request
	reqHost := strings.ToLower(req.Host)
	for _, host := range cfg.Hosts {
		for _, hostname := range host.Hostnames {
			if reqHost == strings.ToLower(hostname) {
				hostForReq = host
				break
			}
		}
	}

	if hostForReq == nil {
		log.Printf("ERROR: no upstream configured")
		return
	}

	u := hostForReq.UpstreamUrl
	req.Header.Add("X-Forwarded-Host", req.Host)
	req.Header.Add("X-Origin-Host", u.Host)
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
}

func main() {
	var err error
	cfg, err = config.Load("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config file: %s", err.Error())
	}

	proxy := &httputil.ReverseProxy{Director: director}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	var wg sync.WaitGroup
	if cfg.HttpPort > 0 {
		wg.Add(1)
		go func() {
			log.Printf("HTTP proxy listening on %s:%d", cfg.ListenAddress, cfg.HttpPort)
			log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.HttpPort), nil))
		}()
	}
	if cfg.HttpsPort > 0 {
		wg.Add(1)
		go func() {
			log.Printf("HTTPS proxy listening on %s:%d", cfg.ListenAddress, cfg.HttpsPort)
			log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.HttpsPort),
				cfg.Tls.Cert, cfg.Tls.Key, nil))
		}()
	}
	wg.Wait()
}
