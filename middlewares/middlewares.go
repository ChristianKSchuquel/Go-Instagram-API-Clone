package middlewares

import (
	"api2/database"
	"api2/utils"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func Auth(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var access_token string
		cookie, err := c.Cookie("access_token")

		authorizationHeader := c.Request.Header.Get("Authorization")
		fields := strings.Fields(authorizationHeader)

		if len(fields) != 0 && fields[0] == "Bearer" {
			access_token = fields[1]
		} else if err == nil {
			access_token = cookie
		}

		if access_token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "You are not logged in"})
			return
		}

		accessTokenPublicKey := database.GetEnvVar("ACCESS_TOKEN_PUBLIC_KEY")

		sub, err := utils.ValidateToken(access_token, accessTokenPublicKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": err.Error()})
			return
		}

		user, found, err := database.GetUser(fmt.Sprint(sub), db)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "The user belonging to this token no logger exists"})
			return
		}

		if found != true {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "User not found"})
		}

		c.Set("currentUser", user)
		c.Next()
	}
}
