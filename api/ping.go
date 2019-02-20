package api

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func getPing(c *gin.Context) {
	c.String(http.StatusOK, "pong")
}

