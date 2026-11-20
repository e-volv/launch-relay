package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	relay, err := NewFromEnvironment()
	if err != nil {
		log.Fatal(err)
	}
	defer relay.Close()
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("e-volv Launch relay listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, relay.Routes()))
}
