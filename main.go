package main

import (
	"github.com/Tabed23/jwt-auth/routes"
	"github.com/gin-gonic/gin"
	"net/http"
)

var port = ":8080"

func main() {
	router := gin.New()
	router.Use(gin.Logger())

	routes.AuthRouting(router)
	routes.UserRouting(router)

	router.GET("/api-1", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	router.Run(port)
}
