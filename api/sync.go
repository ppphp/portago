package api

import (
	"github.com/gin-gonic/gin"
	"github.com/ppphp/portago/sync"
	"net/http"
)

func getSync(c *gin.Context) {
	m, _ := c.GetQuery("method")
	sync.Sync(m)
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.String(http.StatusOK, "{\"a\":1}")
}
