package handler

import (
    "net/http"
    "path/filepath"
    "github.com/gin-gonic/gin"
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

func (h *TemplateHandler) ServeRegisterPageGin(c *gin.Context) {
    c.File(filepath.Join(h.templatesDir, "register.html"))
}

func (h *TemplateHandler) ServeLoginPageGin(c *gin.Context) {
    c.File(filepath.Join(h.templatesDir, "login.html"))
} 