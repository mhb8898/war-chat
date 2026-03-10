package server

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
)

//go:embed web
var webFS embed.FS

type Server struct {
	store           *Store
	hub             *Hub
	hrtHub          *HRTHub
	version         string
	requireApproval bool
}

func New(dataDir, version string) (*Server, error) {
	if version == "" {
		version = "dev"
	}
	store, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}
	_ = store.PruneExpiredRooms()

	hub := NewHub(store)
	go hub.Run()

	hrtHub := NewHRTHub(store)

	s := &Server{
		store:         store,
		hub:           hub,
		hrtHub:        hrtHub,
		version:       version,
		requireApproval: os.Getenv("REQUIRE_APPROVAL") == "true" || os.Getenv("REQUIRE_INVITE") == "true",
	}
	s.setupRoutes()
	return s, nil
}

// AdminConfigured returns whether the admin password has been set up.
func (s *Server) AdminConfigured() bool {
	return s.store.AdminConfigured()
}

func (s *Server) handleStatic() http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	return http.FileServer(http.FS(sub))
}
