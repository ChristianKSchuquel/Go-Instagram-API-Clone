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
		routes.POST("/refresh", api.RefreshAccessToken)
		authorized := routes.Group("/").Use(middlewares.Auth(api.DB))
		{
			authorized.POST("/logout", api.Logout)
			authorized.GET("/user/:id", api.GetUserByID)
			authorized.GET("/user", api.GetUsers)
			authorized.DELETE("/account", api.DeleteUser)
			authorized.PATCH("/account", api.UpdateUser)
			authorized.GET("/account", api.GetCurrentUser)
			authorized.POST("/post", api.CreatePost)
			authorized.GET("post/:postid", api.GetPost)
			authorized.PATCH("post/:postid", api.UpdatePost)
			authorized.DELETE("post/:postid", api.DeletePost)
			authorized.POST("/post/:postid", api.CreateComment)
			authorized.PATCH("post/:postid/:commentid", api.UpdateComment)
			authorized.DELETE("post/:postid/:commentid", api.DeleteComment)
		}
	}

	return r
}
