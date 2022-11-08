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
			authorized.DELETE("/account", api.DeleteUser)
			authorized.PATCH("/account", api.UpdateUser)
			authorized.GET("/account", api.GetCurrentUser)
			authorized.POST("/post", api.CreatePost)
			authorized.GET("post/:postid", api.GetPostFromUser)
			authorized.PATCH("post/:postid", api.UpdatePost)
		}
	}

	return r
}
