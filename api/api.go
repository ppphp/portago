package api

import (
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/contrib/cors"
	"github.com/gin-gonic/gin"
)

var App *gin.Engine

func init() {
	App = gin.Default()
	App.Use(cors.Default())
	App.Use(static.Serve("/", static.LocalFile("./webui/dist/webui", true)))
	App.GET("/ping", getPing)
	App.GET("/sync", getSync)
	App.GET("/category", getCategory)
	App.GET("/package/:category", getPackage)
	App.GET("/build", build)
}
