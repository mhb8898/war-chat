package server

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
)

//go:embed web/*
var webFS embed.FS

type Server struct {
	store   *Store
	hub     *Hub
	version string
}

func New(dataDir, version string) (*Server, error) {
	if version == "" {
		version = "dev"
	}
	store, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}

	hub := NewHub(store)
	go hub.Run()

	s := &Server{store: store, hub: hub, version: version}
	s.setupRoutes()
	return s, nil
}

func (s *Server) handleStatic() http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	return http.FileServer(http.FS(sub))
}
