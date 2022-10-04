package routers

import (
	"api2/database"
	"api2/handlers"
	"api2/middlewares"

	"github.com/gin-gonic/gin"
)

func Setup() *gin.Engine {
	r := gin.Default()

	database.Setup()
	api := &handlers.APIEnv{
		DB: database.GetDB(),
	}

	routes := r.Group("/")
	{
		routes.POST("/signup", api.CreateUser)
		routes.POST("/login", api.Login)
		authorized := routes.Group("/").Use(middlewares.Auth())
		{
			authorized.GET("/user/:id", api.GetUserByID)
			authorized.GET("/user", api.GetUsers)
			authorized.DELETE("/user", api.DeleteUser)
		}
	}

	return r
}
