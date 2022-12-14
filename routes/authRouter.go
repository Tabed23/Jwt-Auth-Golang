package routes

import (
	"github.com/Tabed23/jwt-auth/controller"
	"github.com/gin-gonic/gin"
)


func AuthRouting(routes *gin.Engine){
	routes.POST("user/signup",controller.SignUp)
	routes.POST("user/login",controller.Login)
}
