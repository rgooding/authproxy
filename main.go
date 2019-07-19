package main

import (
	"errors"
	"fmt"
	"github.com/rgooding/http-ldap-auth-proxy/config"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
)

var cfg *config.Config

func hostForRequest(req *http.Request) (*config.HostConfig, error) {
	reqHost := strings.ToLower(req.Host)
	for _, host := range cfg.Hosts {
		for _, hostname := range host.Hostnames {
			if reqHost == strings.ToLower(hostname) {
				return host, nil
			}
		}
	}
	return nil, errors.New("no upstream configured")
}

func main() {
	var err error
	cfg, err = config.Load("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config file: %s", err.Error())
	}

	director := func(req *http.Request) {
		host, err := hostForRequest(req)
		if err != nil {
			log.Printf("ERROR: %s", err.Error())
			return
		}
		upstream, err := url.Parse(host.Upstream)
		if err != nil {
			log.Printf("ERROR: Error parsing upstream URL %s : %s", host.Upstream, err.Error())
			return
		}
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", upstream.Host)
		req.URL.Scheme = "http"
		req.URL.Host = upstream.Host
	}

	proxy := &httputil.ReverseProxy{Director: director}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	var wg sync.WaitGroup
	if cfg.HttpPort > 0 {
		go func() {
			wg.Add(1)
			log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.HttpPort), nil))
		}()
	}
	if cfg.HttpPort > 0 {
		go func() {
			wg.Add(1)
			log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.HttpsPort),
				cfg.Tls.Cert, cfg.Tls.Key, nil))
		}()
	}
	wg.Wait()
}
