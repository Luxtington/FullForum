package handler

import (
    "net/http"
    "path/filepath"
)

type TemplateHandler struct {
    templatesDir string
}

func NewTemplateHandler(templatesDir string) *TemplateHandler {
    return &TemplateHandler{
        templatesDir: templatesDir,
    }
}

func (h *TemplateHandler) ServeRegisterPage(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, filepath.Join(h.templatesDir, "register.html"))
}

func (h *TemplateHandler) ServeLoginPage(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, filepath.Join(h.templatesDir, "login.html"))
} 