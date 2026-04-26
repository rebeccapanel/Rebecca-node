package main

import (
	"log"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	"github.com/rebeccapanel/rebecca-node/internal/maintenance"
)

func main() {
	settings := appconfig.LoadMaintenance()

	server, err := maintenance.New(settings)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Rebecca-node maintenance service running on %s:%d", settings.Host, settings.Port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
