package server

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"io/fs"
	"log"
	"net/http"
)

//go:embed web
var webFS embed.FS

type Server struct {
	store      *Store
	hub        *Hub
	hrtHub     *HRTHub
	version    string
	adminToken string
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

	hrtHub := NewHRTHub(store)

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	adminToken := hex.EncodeToString(b)

	s := &Server{store: store, hub: hub, hrtHub: hrtHub, version: version, adminToken: adminToken}
	s.setupRoutes()
	return s, nil
}

// AdminToken returns the random token for the admin panel path. Used at startup to log the admin URL.
func (s *Server) AdminToken() string {
	return s.adminToken
}

func (s *Server) handleStatic() http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	return http.FileServer(http.FS(sub))
}
