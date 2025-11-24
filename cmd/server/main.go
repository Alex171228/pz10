package main

import (
	"log"
	"net/http"

	"pz10/internal/http/router"
	"pz10/internal/platform/config"
)

func main() {
	cfg := config.Load()

	mux := router.Build(cfg)

	const addr = ":8081" // Жёстко зашитый порт

	log.Println("listening on", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
