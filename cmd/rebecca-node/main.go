package main

import (
	"log"

	"github.com/rebeccapanel/rebecca-node/internal/certutil"
	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	"github.com/rebeccapanel/rebecca-node/internal/node"
)

func main() {
	settings := appconfig.Load()

	if err := certutil.EnsureServerCertificate(settings.SSLCertFile, settings.SSLKeyFile); err != nil {
		log.Fatalf("failed to prepare TLS certificate: %v", err)
	}

	server, err := node.New(settings)
	if err != nil {
		log.Fatalf("failed to initialize node service: %v", err)
	}

	log.Printf("Node service running on :%d", settings.ServicePort)
	if err := server.ListenAndServeTLS(); err != nil {
		log.Fatal(err)
	}
}
