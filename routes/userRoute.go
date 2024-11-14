package routes

import (
	controller"github.com/LidoHon/golang-Jwt/controllers"
	"github.com/LidoHon/golang-Jwt/middleware"
	"github.com/gin-gonic/gin"
)



func UserRoutes(incomingRoutes *gin.Engine){
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users",controller.GetUsers()) 
	incomingRoutes.GET("/users/:user_id", controller.GetUser())
}