package handlers

import (
	"api2/database"
	"api2/models"
	"api2/utils"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type APIEnv struct {
	DB *gorm.DB
}

// ==================================================================
// POST: /signup
// ==================================================================

func (a *APIEnv) CreateUser(c *gin.Context) {
	var newUser models.User

	err := c.BindJSON(&newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		c.Abort()
		return
	}

	newUser.Email = strings.ToLower(newUser.Email)

	// email validation

	if err := a.DB.Where("email = ?", newUser.Email).First(&newUser).Error; err != gorm.ErrRecordNotFound {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		c.Abort()
		return
	}

	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if re.MatchString(newUser.Email) != true {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		c.Abort()
		return
	}

	// password validation

	if isPwdValid := utils.ValidatePwd(newUser.Password); isPwdValid != true {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		c.Abort()
		return
	}

	newPwd, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "An error occurred while hashing the password")
		c.Abort()
		return
	}

	newUser.Password = string(newPwd[:])

	// name validation

	if len(newUser.Name) < 2 || len(newUser.Name) > 35 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		c.Abort()
		return
	}

	newUser.Gender = strings.ToLower(newUser.Gender)

	newUser.ID, err = utils.GenUserID(a.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while creating the user id"})
		c.Abort()
		return
	}

	a.DB.Create(&newUser)
	c.JSON(http.StatusCreated, gin.H{"Created User Successfully": newUser})
}

// ==================================================================
// POST: /login
// ==================================================================

func (a *APIEnv) Login(c *gin.Context) {
	var loginDto models.LoginDTO
	var user models.User

	errBind := c.BindJSON(&loginDto)
	if errBind != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errBind})
		c.Abort()
		return
	}

	err := a.DB.Where("email = ?", loginDto.Email).First(&user).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while getting the user info"})
		c.Abort()
		return
	}

	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		c.Abort()
		return
	}

	pwdCheck := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginDto.Password))
	if pwdCheck != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		c.Abort()
		return
	}

	token, err := utils.GenToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Users not found"})
		c.Abort()
		return
	}

	c.JSON(http.StatusOK, gin.H{"User": user})
}

// ==================================================================
// GET: /user
// ==================================================================

func (a *APIEnv) GetUsers(c *gin.Context) {
	var users []models.User

	users, exists, err := database.GetAllUsers(a.DB)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Users not found"})
		c.Abort()
		return
	}

	c.JSON(http.StatusOK, gin.H{"Users": users})
}

// ==================================================================
// DELETE: /account
// ==================================================================

func (a *APIEnv) DeleteUser(c *gin.Context) {
	token := c.GetHeader("Authorization")

	user, err := utils.CheckJWTUserID(token, a.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		c.Abort()
		return
	}

	a.DB.Delete(&user)

	c.JSON(http.StatusOK, gin.H{"User deleted successfully": user})
}

// ==================================================================
// PATCH: /account
// ==================================================================

func (a *APIEnv) UpdateUser(c *gin.Context) {
	token := c.GetHeader("Authorization")

	user, err := utils.CheckJWTUserID(token, a.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		c.Abort()
		return
	}

	var loginDto models.LoginDTO

	errBind := c.BindJSON(&loginDto)
	if errBind != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errBind})
		c.Abort()
		return
	}

	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if re.MatchString(loginDto.Email) != true {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		c.Abort()
		return
	}

	if isPwdValid := utils.ValidatePwd(loginDto.Password); isPwdValid != true {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		c.Abort()
		return
	}

	newPwd, err := bcrypt.GenerateFromPassword([]byte(loginDto.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "An error occurred while hashing the password")
		c.Abort()
		return
	}

	if len(loginDto.Name) < 2 || len(loginDto.Name) > 35 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials name"})
		c.Abort()
		return
	}

	loginDto.Password = string(newPwd[:])

	user.Name = loginDto.Name
	user.Email = loginDto.Email
	user.Password = loginDto.Password
	user.Gender = loginDto.Gender
	user.Gender = strings.ToLower(loginDto.Gender)

	a.DB.Save(&user)

	c.JSON(http.StatusOK, gin.H{"User updated successfully": user})
}

// ==================================================================
// GET: /account
// ==================================================================

func (a *APIEnv) GetCurrentUser(c *gin.Context) {
	token := c.GetHeader("Authorization")

	user, err := utils.CheckJWTUserID(token, a.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		c.Abort()
		return
	}

	c.JSON(http.StatusOK, gin.H{"User": user})
}

// ==================================================================
// POST: /post
// ==================================================================

func (a *APIEnv) CreatePost(c *gin.Context) {
	token := c.GetHeader("Authorization")

	user, err := utils.CheckJWTUserID(token, a.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		c.Abort()
		return
	}

	var newPost models.Post

	errBind := c.BindJSON(&newPost)
	if errBind != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errBind})
		c.Abort()
		return
	}

	newPost.ID, err = utils.GenPostID(a.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while creating the user id"})
		c.Abort()
		return
	}
	post := []models.Post{newPost}
	user.Posts = append(post)

	if len(newPost.Title) < 2 || len(newPost.Title) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid title length: title should be at least 2 characters and at max 100"})
		c.Abort()
		return
	}

	if len(newPost.Content) < 10 || len(newPost.Content) > 300 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid content length: content should be at least 10 characters and at max 300"})
		c.Abort()
		return
	}

	a.DB.Save(&user)
	c.JSON(http.StatusOK, gin.H{"Post created successfully": newPost})
}

// ==================================================================
// GET: /post/:postid
// ==================================================================

func (a *APIEnv) GetPostFromUser(c *gin.Context) {
	postId := c.Params.ByName("postid")
	post := models.Post{}

	err := a.DB.First(&post, postId).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": err})
		c.Abort()
		return
	}

	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusBadRequest, gin.H{"Error": err})
		c.Abort()
		return
	}

	c.JSON(http.StatusOK, gin.H{"Post": post})
}

// ==================================================================
// PATCH: /post/:postid
// ==================================================================

func (a *APIEnv) UpdatePost(c *gin.Context) {
	postId := c.Params.ByName("postid")
	post := models.Post{}

	err := a.DB.First(&post, postId).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": err})
		c.Abort()
		return
	}
	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Post not found"})
		c.Abort()
		return
	}

	token := c.GetHeader("Authorization")

	user, err := utils.CheckJWTUserID(token, a.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		c.Abort()
		return
	}

	if user.ID != post.UserID {
		c.JSON(http.StatusUnauthorized, gin.H{"Unauthorized": "You're not the owner of this post"})
		c.Abort()
		return
	}

	var newPost models.Post

	errBind := c.BindJSON(&newPost)
	if errBind != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errBind})
		c.Abort()
		return
	}

	if len(newPost.Title) < 2 || len(newPost.Title) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid title length: title should be at least 2 characters and at max 100"})
		c.Abort()
		return
	}

	if len(newPost.Content) < 10 || len(newPost.Content) > 300 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid content length: content should be at least 10 characters and at max 300"})
		c.Abort()
		return
	}

	post.Title = newPost.Title
	post.Content = newPost.Content
	post.UpdatedAt = time.Now()

	a.DB.Save(&post)
	c.JSON(http.StatusOK, gin.H{"Post": "post updated successfully"})
}
