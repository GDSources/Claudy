package middleware

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityConfig holds configuration for security headers middleware
type SecurityConfig struct {
	ContentSecurityPolicy   string                            // Content-Security-Policy header value
	XFrameOptions          string                            // X-Frame-Options header value
	XContentTypeOptions    string                            // X-Content-Type-Options header value
	ReferrerPolicy         string                            // Referrer-Policy header value
	StrictTransportSecurity StrictTransportSecurityConfig    // HSTS configuration
	XSSProtection          XSSProtectionConfig               // XSS Protection configuration
	PermissionsPolicy      map[string][]string               // Permissions-Policy directives
	CustomHeaders          map[string]string                 // Custom security headers
}

// StrictTransportSecurityConfig holds HSTS configuration
type StrictTransportSecurityConfig struct {
	MaxAge            int  // Max age in seconds
	IncludeSubDomains bool // Include subdomains
	Preload           bool // Include preload directive
}

// XSSProtectionConfig holds XSS protection configuration
type XSSProtectionConfig struct {
	Enable bool   // Whether to enable XSS protection
	Mode   string // XSS protection mode (e.g., "block")
}

// NewSecurityHeadersMiddleware creates a new security headers middleware
func NewSecurityHeadersMiddleware(config SecurityConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set Content Security Policy
		if config.ContentSecurityPolicy != "" {
			c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
		}

		// Set X-Frame-Options
		if config.XFrameOptions != "" {
			c.Header("X-Frame-Options", config.XFrameOptions)
		}

		// Set X-Content-Type-Options
		if config.XContentTypeOptions != "" {
			c.Header("X-Content-Type-Options", config.XContentTypeOptions)
		}

		// Set Referrer-Policy
		if config.ReferrerPolicy != "" {
			c.Header("Referrer-Policy", config.ReferrerPolicy)
		}

		// Set Strict-Transport-Security (only for HTTPS)
		if isHTTPS(c) && config.StrictTransportSecurity.MaxAge > 0 {
			hstsValue := buildHSTSHeader(config.StrictTransportSecurity)
			c.Header("Strict-Transport-Security", hstsValue)
		}

		// Set X-XSS-Protection
		if config.XSSProtection.Enable {
			xssValue := buildXSSProtectionHeader(config.XSSProtection)
			c.Header("X-XSS-Protection", xssValue)
		} else {
			// Explicitly disable XSS protection if configured
			c.Header("X-XSS-Protection", "0")
		}

		// Set Permissions-Policy
		if len(config.PermissionsPolicy) > 0 {
			permissionsValue := buildPermissionsPolicyHeader(config.PermissionsPolicy)
			c.Header("Permissions-Policy", permissionsValue)
		}

		// Set custom headers
		for key, value := range config.CustomHeaders {
			c.Header(key, value)
		}

		c.Next()
	}
}

// isHTTPS determines if the request is using HTTPS
func isHTTPS(c *gin.Context) bool {
	// Check X-Forwarded-Proto header (common in load balancers/proxies)
	if proto := c.GetHeader("X-Forwarded-Proto"); proto == "https" {
		return true
	}

	// Check if TLS is used directly
	if c.Request.TLS != nil {
		return true
	}

	// Check scheme in request URL
	if c.Request.URL.Scheme == "https" {
		return true
	}

	return false
}

// buildHSTSHeader builds the Strict-Transport-Security header value
func buildHSTSHeader(config StrictTransportSecurityConfig) string {
	parts := []string{
		"max-age=" + strconv.Itoa(config.MaxAge),
	}

	if config.IncludeSubDomains {
		parts = append(parts, "includeSubDomains")
	}

	if config.Preload {
		parts = append(parts, "preload")
	}

	return strings.Join(parts, "; ")
}

// buildXSSProtectionHeader builds the X-XSS-Protection header value
func buildXSSProtectionHeader(config XSSProtectionConfig) string {
	if !config.Enable {
		return "0"
	}

	value := "1"
	if config.Mode != "" {
		value += "; mode=" + config.Mode
	}

	return value
}

// buildPermissionsPolicyHeader builds the Permissions-Policy header value
func buildPermissionsPolicyHeader(policies map[string][]string) string {
	var parts []string

	for directive, allowlist := range policies {
		allowlistStr := strings.Join(allowlist, " ")
		parts = append(parts, fmt.Sprintf("%s=(%s)", directive, allowlistStr))
	}

	return strings.Join(parts, ", ")
}