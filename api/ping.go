package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func getPing(c *gin.Context) {
	c.String(http.StatusOK, "pong")
}
