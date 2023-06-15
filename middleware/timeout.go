package middleware

import (
	"net/http"
	"time"

	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
)

const RequestTimeout = "5s"

func timeoutResponse(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusRequestTimeout, gin.H{
		"status": http.StatusRequestTimeout,
		"error":  []string{"reqest timeout"},
	})
}

func Timeout() gin.HandlerFunc {
	duration, _ := time.ParseDuration(RequestTimeout)
	return timeout.New(
		timeout.WithTimeout(duration),
		timeout.WithHandler(func(c *gin.Context) {
			c.Next()
		}),
		timeout.WithResponse(timeoutResponse),
	)
}
