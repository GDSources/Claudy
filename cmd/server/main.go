package main

import (
	"log"

	"claudy/internal/server"
)

func main() {
	app := server.NewServer()
	if err := app.Run(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}