package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed templates/* static/*
var embeddedFiles embed.FS

// StaticFS returns an http.FileSystem serving the embedded static assets.
func StaticFS() http.FileSystem {
	sub, err := fs.Sub(embeddedFiles, "static")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}

// ReadIndexHTML returns the raw bytes of the embedded index.html template.
func ReadIndexHTML() ([]byte, error) {
	return embeddedFiles.ReadFile("templates/index.html")
}
