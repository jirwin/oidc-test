package main

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jirwin/oidc-test/internal/config"
	"github.com/jirwin/oidc-test/internal/db"
	"github.com/jirwin/oidc-test/internal/router"
)

var version = "dev"

//go:embed templates/*.html templates/**/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-version" {
		fmt.Println("oidc-test", version)
		os.Exit(0)
	}
	cfg := config.Parse()

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()

	// Start background cleanup
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := db.Cleanup(database); err != nil {
				log.Printf("Cleanup error: %v", err)
			}
		}
	}()

	templates, err := parseTemplates()
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("Failed to get static sub-fs: %v", err)
	}

	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	handler := router.New(database, baseURL, templates, staticSub, cfg)

	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("Starting OIDC test provider on %s (base URL: %s)", addr, baseURL)
	log.Fatal(http.ListenAndServe(addr, handler))
}

// Templates is a map of page name -> compiled template (layout + page).
type Templates = map[string]*template.Template

func parseTemplates() (Templates, error) {
	layoutData, err := templateFS.ReadFile("templates/layout.html")
	if err != nil {
		return nil, fmt.Errorf("read layout: %w", err)
	}

	pages := map[string]string{
		"dashboard.html":    "templates/admin/dashboard.html",
		"issuer_form.html":  "templates/admin/issuer_form.html",
		"issuer_detail.html": "templates/admin/issuer_detail.html",
		"client_form.html":  "templates/admin/client_form.html",
		"login.html":        "templates/auth/login.html",
		"consent.html":      "templates/auth/consent.html",
	}

	result := make(Templates, len(pages))
	for name, path := range pages {
		t, err := template.New("layout").Parse(string(layoutData))
		if err != nil {
			return nil, fmt.Errorf("parse layout for %s: %w", name, err)
		}
		pageData, err := templateFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if _, err := t.Parse(string(pageData)); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		result[name] = t
	}

	return result, nil
}
