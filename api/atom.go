package api

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/json"
	"github.com/ppphp/portago/atom"
	"net/http"
)

func getCategory(c *gin.Context) {
	cs := atom.IndexCategories()
	var s string
	if cs== nil {
		s="{}"
	}else {
		b, err := json.Marshal(cs)
		if err != nil {

			s="{}"
		} else {

			s = string(b)
		}
	}
	c.String(http.StatusOK, s)
}


func getPackage(c *gin.Context) {
	cs := atom.IndexCategories()
	var s string
	if cs== nil {
		s="{}"
	}else {
		b, err := json.Marshal(cs)
		if err != nil {

			s="{}"
		} else {

			s = string(b)
		}
	}
	c.String(http.StatusOK, s)
}

func build(c *gin.Context) {
	atom.Build()
}


