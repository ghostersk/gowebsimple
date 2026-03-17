package handlers

import (
	"net/http"
)

// ErrorData is passed to the error template.
type ErrorData struct {
	PageData
	StatusCode int
	StatusText string
	Detail     string
}

// ErrorHandler renders stylish error pages using the base layout.
type ErrorHandler struct {
	tmpl *Renderer
}

func NewErrorHandler(r *Renderer) *ErrorHandler {
	return &ErrorHandler{tmpl: r}
}

// NotFound renders a 404 page.
func (h *ErrorHandler) NotFound(w http.ResponseWriter, r *http.Request) {
	h.renderError(w, r, http.StatusNotFound,
		"Page Not Found",
		"The page you're looking for doesn't exist or has been moved.")
}

// Forbidden renders a 403 page.
func (h *ErrorHandler) Forbidden(w http.ResponseWriter, r *http.Request) {
	h.renderError(w, r, http.StatusForbidden,
		"Access Forbidden",
		"You don't have permission to access this page.")
}

// InternalError renders a 500 page.
func (h *ErrorHandler) InternalError(w http.ResponseWriter, r *http.Request) {
	h.renderError(w, r, http.StatusInternalServerError,
		"Internal Server Error",
		"Something went wrong on our end. Please try again later.")
}

// RenderError renders an error page with a custom status, title, and detail message.
func (h *ErrorHandler) RenderError(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	h.renderError(w, r, status, title, detail)
}

func (h *ErrorHandler) renderError(w http.ResponseWriter, r *http.Request, status int, statusText, detail string) {
	pd := NewPageData(r, statusText)
	data := ErrorData{
		PageData:   pd,
		StatusCode: status,
		StatusText: statusText,
		Detail:     detail,
	}
	h.tmpl.RenderStatus(w, status, "error", data)
}
