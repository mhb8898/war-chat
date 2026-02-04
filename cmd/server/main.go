package main

import (
	"log"
	"net/http"
	"os"

	"github.com/war-chat/war-chat/internal/server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		runHealthcheck()
		return
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	_, err := server.New(dataDir)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("War Chat server listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func runHealthcheck() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	resp, err := http.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		os.Exit(1)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	os.Exit(0)
}
