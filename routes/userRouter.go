package routes

import (
	"github.com/Tabed23/jwt-auth/controller"
	"github.com/Tabed23/jwt-auth/middleware"
	"github.com/gin-gonic/gin"
)


func UserRouting(routes *gin.Engine){
	routes.Use(middleware.Authenticate())

	routes.GET("/users", controller.GetUsers)
	routes.GET("/users/:user_id", controller.GetUser)
}
