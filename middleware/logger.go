package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
)

// Logger middleware logs the request details
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		// Process request
		c.Next()

		// Log details
		latency := time.Since(start)
		statusCode := c.Writer.Status()
		gin.DefaultWriter.Write([]byte(
			"[GIN] " + c.Request.Method + " | " +
				path + " | " +
				string(rune(statusCode)) + " | " +
				latency.String() + "\n",
		))
	}
}
