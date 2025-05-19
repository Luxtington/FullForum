package handler

import (
    _"path/filepath"
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

func (h *TemplateHandler) ServeRegisterPage(c *gin.Context) {
    c.File(filepath.Join(h.templatesDir, "register.html"))
}

func (h *TemplateHandler) ServeLoginPage(c *gin.Context) {
    c.File(filepath.Join(h.templatesDir, "login.html"))
} 