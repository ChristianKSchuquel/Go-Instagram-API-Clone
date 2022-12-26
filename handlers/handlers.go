package handlers

import (
	"api2/database"
	"api2/models"
	"api2/utils"
	"log"
    "fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type APIEnv struct {
	DB *gorm.DB
}


    var accessTokenPrivateKey = database.GetEnvVar("ACCESS_TOKEN_PRIVATE_KEY")
    var accessTokenPublicKey = database.GetEnvVar("ACCESS_TOKEN_PUBLIC_KEY")
    var refreshTokenPrivateKey = database.GetEnvVar("REFRESH_TOKEN_PRIVATE_KEY")
    var refreshTokenPublicKey = database.GetEnvVar("REFRESH_TOKEN_PUBLIC_KEY")
    var refreshTokenMaxAge = database.GetEnvVar("REFRESH_TOKEN_MAXAGE")
    var accessTokenMaxAge = database.GetEnvVar("ACCESS_TOKEN_MAXAGE")

// ==================================================================
// POST: /signup
// ==================================================================

func (a *APIEnv) CreateUser(c *gin.Context) {
	var newUser models.User

	err := c.BindJSON(&newUser)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err})
		
		return
	}

	newUser.Email = strings.ToLower(newUser.Email)

	// email validation

	if err := a.DB.Where("email = ?", newUser.Email).First(&newUser).Error; err != gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Email alreay in use"})
		
		return
	}

	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if re.MatchString(newUser.Email) != true {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid Email"})
		
		return
	}

	// password validation

	if isPwdValid := utils.ValidatePwd(newUser.Password); isPwdValid != true {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid Password, must be at least 7 characters long and must contain at least 1 lowercase letter, 1 upercase letter, 1 number and 1 special character"})
		
		return
	}

	newPwd, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, "An error occurred while hashing the password")
		
		return
	}

	newUser.Password = string(newPwd[:])

	// name validation

	if len(newUser.Name) < 2 || len(newUser.Name) > 35 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid Name, must be at least 2 characters and at max 35 characters"})
		
		return
	}

	newUser.Gender = strings.ToLower(newUser.Gender)

	newUser.ID = utils.GenID(a.DB, models.User{})

	a.DB.Create(&newUser)
	c.AbortWithStatusJSON(http.StatusCreated, gin.H{"Created User Successfully": newUser})
}

// ==================================================================
// POST: /login
// ==================================================================

func (a *APIEnv) Login(c *gin.Context) {
	var UserDTO models.UserDTO
	var user models.User

	errBind := c.BindJSON(&UserDTO)
	if errBind != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": errBind})
		
		return
	}

	err := a.DB.Where("email = ?", UserDTO.Email).First(&user).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while getting the user info"})
		
		return
	}

	if err == gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Invalid Credentials"})
		
		return
	}

	pwdCheck := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(UserDTO.Password))
	if pwdCheck != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		
		return
	}

    accessTokenMaxAgeInt, err := strconv.ParseInt(accessTokenMaxAge, 10, 32)
    refreshTokenMaxAgeInt, err := strconv.ParseInt(refreshTokenMaxAge, 10, 32)

	access_token, err := utils.GenToken(int(accessTokenMaxAgeInt), user.ID, accessTokenPrivateKey)
    if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	refresh_token, err := utils.GenToken(int(refreshTokenMaxAgeInt), user.ID, refreshTokenPrivateKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

    c.SetCookie("access_token", access_token, int(accessTokenMaxAgeInt)*60, "/", "localhost", false, true)
    c.SetCookie("refresh_token", refresh_token, int(refreshTokenMaxAgeInt)*60, "/", "localhost", false, true)
    c.SetCookie("logged_in", "true", int(accessTokenMaxAgeInt)*60, "/", "localhost", false, false)

	c.AbortWithStatusJSON(http.StatusOK, gin.H{"token": access_token})
}

// ==================================================================
// POST: /refresh
// ==================================================================

func(a *APIEnv) RefreshAccessToken(c *gin.Context) {

	cookie, err := c.Cookie("refresh_token")
	if err != nil {
        c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Could not get refresh token"})
		return
	}

	sub, err := utils.ValidateToken(cookie, refreshTokenPublicKey)
	if err != nil {
        c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Could not validate token", "message": err})
		return
	}

    user, found, err := database.GetUser(fmt.Sprint(sub), a.DB)
    if err != nil && err != gorm.ErrRecordNotFound {
        c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H {"error": err})
    }
    if found != true {
        c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error":"token owner does not exist"})
    }

    accessTokenMaxAgeInt, err := strconv.ParseInt(accessTokenMaxAge, 10, 32)

	access_token, err := utils.GenToken(int(accessTokenMaxAgeInt), user.ID, accessTokenPrivateKey)
    if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

    c.SetCookie("access_token", access_token, int(accessTokenMaxAgeInt)*60, "/", "localhost", false, true)
    c.SetCookie("logged_in", "true", int(accessTokenMaxAgeInt)*60, "/", "localhost", false, false)

	c.JSON(http.StatusOK, gin.H{"access_token": access_token})
}

// ==================================================================
// POST: /logout
// ==================================================================

func(a *APIEnv) Logout(c *gin.Context) {
    c.SetCookie("access_token", "", -1, "/", "localhost", false, true)
	c.SetCookie("refresh_token", "", -1, "/", "localhost", false, true)
	c.SetCookie("logged_in", "", -1, "/", "localhost", false, true)

    c.JSON(http.StatusOK, gin.H{"success": "logged out"})
}

// ==================================================================
// GET: /user/:id
// ==================================================================

func (a *APIEnv) GetUserByID(c *gin.Context) {
	var user models.User

	id := c.Params.ByName("id")
	user, exists, err := database.GetUser(id, a.DB)
	if err != nil {
		log.Println(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		
		return
	}

	if !exists {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Users not found"})
		
		return
	}

	c.AbortWithStatusJSON(http.StatusOK, gin.H{"User": user})
}

// ==================================================================
// GET: /user
// ==================================================================

func (a *APIEnv) GetUsers(c *gin.Context) {
	var users []models.User

	users, exists, err := database.GetAllUsers(a.DB)
	if err != nil {
		log.Println(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		
		return
	}

	if !exists {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Users not found"})
		
		return
	}

	c.AbortWithStatusJSON(http.StatusOK, gin.H{"Users": users})
}

// ==================================================================
// DELETE: /account
// ==================================================================

func (a *APIEnv) DeleteUser(c *gin.Context) {
	token, err := c.Cookie("access_token")
    if err != nil {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "access token not found"})
    }

	user, err := utils.GetUserByJWT(token, a.DB, accessTokenPublicKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err})
		
		return
	}

	a.DB.Delete(&user)

	c.AbortWithStatusJSON(http.StatusOK, gin.H{"User deleted successfully": user})
}

// ==================================================================
// PATCH: /account
// ==================================================================

func (a *APIEnv) UpdateUser(c *gin.Context) {
	token, err := c.Cookie("access_token")
    if err != nil {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "access token not found"})
    }

	user, err := utils.GetUserByJWT(token, a.DB, accessTokenPublicKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err})
		
		return
	}

	var UserDTO models.UserDTO

	errBind := c.BindJSON(&UserDTO)
	if errBind != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": errBind})
		
		return
	}

	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if re.MatchString(UserDTO.Email) != true {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		
		return
	}

	if isPwdValid := utils.ValidatePwd(UserDTO.Password); isPwdValid != true {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		
		return
	}

	newPwd, err := bcrypt.GenerateFromPassword([]byte(UserDTO.Password), bcrypt.DefaultCost)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, "An error occurred while hashing the password")
		
		return
	}

	if len(UserDTO.Name) < 2 || len(UserDTO.Name) > 35 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials name"})
		
		return
	}

	UserDTO.Password = string(newPwd[:])

	user.Name = UserDTO.Name
	user.Email = UserDTO.Email
	user.Password = UserDTO.Password
	user.Gender = UserDTO.Gender
	user.Gender = strings.ToLower(UserDTO.Gender)

	a.DB.Save(&user)

	c.AbortWithStatusJSON(http.StatusOK, gin.H{"User updated successfully": user})
}

// ==================================================================
// GET: /account
// ==================================================================

func (a *APIEnv) GetCurrentUser(c *gin.Context) {
    token, err := c.Cookie("access_token")
    if err != nil {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "access token not found"})
    }

	user, err := utils.GetUserByJWT(token, a.DB, accessTokenPublicKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err})
		return
	}

	c.AbortWithStatusJSON(http.StatusOK, gin.H{"User": user})
}

// ==================================================================
// POST: /post
// ==================================================================

func (a *APIEnv) CreatePost(c *gin.Context) {
	token, err := c.Cookie("access_token")
    if err != nil {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "access token not found"})
    }

	user, err := utils.GetUserByJWT(token, a.DB, accessTokenPublicKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err})
		
		return
	}
	var newPost models.Post

	errBind := c.BindJSON(&newPost)
	if errBind != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": errBind})
		
		return
	}

	newPost.ID = utils.GenID(a.DB, models.Post{})

	post := []models.Post{newPost}
	user.Posts = append(post)
    newPost.UserID = user.ID

	if len(newPost.Title) < 2 || len(newPost.Title) > 100 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid title length: title should be at least 2 characters and at max 100"})
		
		return
	}

	if len(newPost.Content) < 10 || len(newPost.Content) > 300 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid content length: content should be at least 10 characters and at max 300"})
		
		return
	}

	a.DB.Save(&user)
	c.AbortWithStatusJSON(http.StatusOK, gin.H{"Post created successfully": newPost})
}

// ==================================================================
// GET: /post/:postid
// ==================================================================

func (a *APIEnv) GetPost(c *gin.Context) {
	postId := c.Params.ByName("postid")
	post := models.Post{}

	err := a.DB.Preload("Comments").First(&post, postId).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Error": err})
		return
	}

	if err == gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"Error": "post not found"})
		return
	}

	c.AbortWithStatusJSON(http.StatusOK, gin.H{"Post": post})
}

// ==================================================================
// PATCH: /post/:postid
// ==================================================================

func (a *APIEnv) UpdatePost(c *gin.Context) {
	postId := c.Params.ByName("postid")
	post := models.Post{}

	err := a.DB.First(&post, postId).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Error": err})
		
		return
	}
	if err == gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"Error": "Post not found"})
		
		return
	}

	token, err := c.Cookie("access_token")
    if err != nil {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "access token not found"})
    }

	user, err := utils.GetUserByJWT(token, a.DB, accessTokenPublicKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err})
		
		return
	}

	if user.ID != post.UserID {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Unauthorized": "You're not the owner of this post"})
		
		return
	}

	var newPost models.Post

	errBind := c.BindJSON(&newPost)
	if errBind != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": errBind})
		
		return
	}

	if len(newPost.Title) < 2 || len(newPost.Title) > 100 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid title length: title should be at least 2 characters and at max 100"})
		
		return
	}

	if len(newPost.Content) < 10 || len(newPost.Content) > 300 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid content length: content should be at least 10 characters and at max 300"})
		
		return
	}

	post.Title = newPost.Title
	post.Content = newPost.Content

	a.DB.Save(&post)
	c.AbortWithStatusJSON(http.StatusOK, gin.H{"Post": "post updated successfully"})
}

// ==================================================================
// DELETE: /post/:postid
// ==================================================================

func (a *APIEnv) DeletePost(c *gin.Context) {
	token, err := c.Cookie("access_token")
    if err != nil {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "access token not found"})
    }

	postID := c.Params.ByName("postid")
	post := models.Post{}

	err = a.DB.First(&post, postID).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err})
		
		return
	}

	if err == gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Post not found"})
		
		return
	}

	user, err := utils.GetUserByJWT(token, a.DB, accessTokenPublicKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err})
		
		return
	}

	if post.UserID != user.ID {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "You're not the owner of this post"})
		
		return
	}

	a.DB.Delete(&post)

	c.AbortWithStatusJSON(http.StatusOK, gin.H{"User deleted successfully": post})
}

// ==================================================================
// POST: /post/:postid
// ==================================================================

func (a *APIEnv) CreateComment(c *gin.Context) {
	postId := c.Params.ByName("postid")
	post := models.Post{}

	err := a.DB.First(&post, postId).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Error": err})
		
		return
	}
	if err == gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"Error": "Post not found"})
		
		return
	}

	token, err := c.Cookie("access_token")
    if err != nil {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "access token not found"})
    }

	user, err := utils.GetUserByJWT(token, a.DB, accessTokenPublicKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err})
		
		return
	}

	var newComment models.Comment

	errBind := c.BindJSON(&newComment)
	if errBind != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": errBind})
		
		return
	}

    newComment.UserID = user.ID

	newComment.ID = utils.GenID(a.DB, models.Comment{})

    newComment.PostID = post.ID

	comment := []models.Comment{newComment}
	user.Comments = append(comment)

    a.DB.Save(&user)
	c.AbortWithStatusJSON(http.StatusOK, gin.H{"Comment created successfully": newComment})
}

// ==================================================================
// PATCH: /post/:postid/:commentid
// ==================================================================


func (a *APIEnv) UpdateComment(c *gin.Context) {
	commentId := c.Params.ByName("commentid")
	postId := c.Params.ByName("postid")
    comment := models.Comment{}

    err := a.DB.First(&comment, commentId).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Error": err})
		
		return
	}
	if err == gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"Error": "Comment not found"})
		
		return
	}

	token, err := c.Cookie("access_token")
    if err != nil {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "access token not found"})
    }

	user, err := utils.GetUserByJWT(token, a.DB, accessTokenPublicKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Error": err})
		
		return
	}

    if comment.UserID != user.ID {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Unauthorized": "You're not the owner of this post"})
		
		return
    }

    postIdUint, err := strconv.ParseUint(postId, 0, 64)
    if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Error": err})
		
		return
    }

    if comment.PostID != uint(postIdUint) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Unauthorized": "PostID of the comment doesn't match the postID provided by the user'"})
		
		return
    }

	var newComment models.Comment

	errBind := c.BindJSON(&newComment)
	if errBind != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Error": errBind})
		
		return
	}
    
    comment.Content = newComment.Content

    a.DB.Save(&comment)
    c.AbortWithStatusJSON(http.StatusOK, gin.H{"Comment updated Successfully": comment})
}

// ==================================================================
// DELETE: /post/:postid/:commentid
// ==================================================================

func(a *APIEnv) DeleteComment(c *gin.Context) {
	commentId := c.Params.ByName("commentid")
	postId := c.Params.ByName("postid")
    comment := models.Comment{}

    err := a.DB.First(&comment, commentId).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Error": err})
		
		return
	}
	if err == gorm.ErrRecordNotFound {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"Error": "Comment not found"})
		
		return
	}

	token, err := c.Cookie("access_token")
    if err != nil {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "access token not found"})
    }

	user, err := utils.GetUserByJWT(token, a.DB, accessTokenPublicKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Error": err})
		
		return
	}

    if comment.UserID != user.ID {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Unauthorized": "You're not the owner of this comment"})
		
		return
    }

    postIdUint, err := strconv.ParseUint(postId, 0, 64)
    if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Error": err})
		return
    }

    if comment.PostID != uint(postIdUint) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Unauthorized": "PostID of the comment doesn't match the postID provided by the user'"})
		return
    }

    a.DB.Delete(&comment)
    c.AbortWithStatusJSON(http.StatusOK, gin.H{"Success": "Comment Deleted Successfully"})
}
