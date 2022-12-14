package middleware

import (
	"fmt"
	"net/http"

	"github.com/Tabed23/jwt-auth/helper"
	"github.com/gin-gonic/gin"
)

func Authenticate() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		clientToken := ctx.Request.Header.Get("token")
		if clientToken == "" {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("No  Authenticate has provided")})
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}
		claims, err := helper.ValidateToken(clientToken)
		if err != "" {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err})
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}

		ctx.Set("email", claims.Email)
		ctx.Set("first_name", claims.FirstName)
		ctx.Set("last_name", claims.LastName)
		ctx.Set("uuid", claims.Uid)
		ctx.Set("user_type", claims.UserType)
		ctx.Next()
	}
}
