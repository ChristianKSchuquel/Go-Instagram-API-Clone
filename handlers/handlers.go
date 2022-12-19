package handlers

import (
	"api2/database"
	"api2/models"
	"api2/utils"
	"log"
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
	var UserDTO models.UserDTO
	var user models.User

	errBind := c.BindJSON(&UserDTO)
	if errBind != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errBind})
		c.Abort()
		return
	}

	err := a.DB.Where("email = ?", UserDTO.Email).First(&user).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while getting the user info"})
		c.Abort()
		return
	}

	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error": "Invalid Credentials"})
		c.Abort()
		return
	}

	pwdCheck := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(UserDTO.Password))
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
		c.Abort()
		return
	}

	var UserDTO models.UserDTO

	errBind := c.BindJSON(&UserDTO)
	if errBind != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errBind})
		c.Abort()
		return
	}

	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if re.MatchString(UserDTO.Email) != true {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		c.Abort()
		return
	}

	if isPwdValid := utils.ValidatePwd(UserDTO.Password); isPwdValid != true {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
		c.Abort()
		return
	}

	newPwd, err := bcrypt.GenerateFromPassword([]byte(UserDTO.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "An error occurred while hashing the password")
		c.Abort()
		return
	}

	if len(UserDTO.Name) < 2 || len(UserDTO.Name) > 35 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials name"})
		c.Abort()
		return
	}

	UserDTO.Password = string(newPwd[:])

	user.Name = UserDTO.Name
	user.Email = UserDTO.Email
	user.Password = UserDTO.Password
	user.Gender = UserDTO.Gender
	user.Gender = strings.ToLower(UserDTO.Gender)

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
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
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

func (a *APIEnv) GetPost(c *gin.Context) {
	postId := c.Params.ByName("postid")
	post := models.Post{}

	err := a.DB.Preload("Comments").First(&post, postId).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": err})
		c.Abort()
		return
	}

	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusNotFound, gin.H{"Error": err})
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
		c.JSON(http.StatusNotFound, gin.H{"Error": "Post not found"})
		c.Abort()
		return
	}

	token := c.GetHeader("Authorization")

	user, err := utils.CheckJWTUserID(token, a.DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
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

	a.DB.Save(&post)
	c.JSON(http.StatusOK, gin.H{"Post": "post updated successfully"})
}

// ==================================================================
// DELETE: /post/:postid
// ==================================================================

func (a *APIEnv) DeletePost(c *gin.Context) {
	token := c.GetHeader("Authorization")
	postID := c.Params.ByName("postid")
	post := models.Post{}

	err := a.DB.First(&post, postID).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		c.Abort()
		return
	}

	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error": "Post not found"})
		c.Abort()
		return
	}

	user, err := utils.CheckJWTUserID(token, a.DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
		c.Abort()
		return
	}

	if post.UserID != user.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You're not the owner of this post"})
		c.Abort()
		return
	}

	a.DB.Delete(&post)

	c.JSON(http.StatusOK, gin.H{"User deleted successfully": post})
}

// ==================================================================
// POST: /post/:postid
// ==================================================================

func (a *APIEnv) CreateComment(c *gin.Context) {
	postId := c.Params.ByName("postid")
	post := models.Post{}

	err := a.DB.First(&post, postId).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": err})
		c.Abort()
		return
	}
	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusNotFound, gin.H{"Error": "Post not found"})
		c.Abort()
		return
	}

	token := c.GetHeader("Authorization")

	user, err := utils.CheckJWTUserID(token, a.DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
		c.Abort()
		return
	}

	var newComment models.Comment

	errBind := c.BindJSON(&newComment)
	if errBind != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errBind})
		c.Abort()
		return
	}

    newComment.UserID = user.ID

	newComment.ID, err = utils.GenPostID(a.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while creating the comment id"})
		c.Abort()
		return
	}

    newComment.PostID = post.ID

	comment := []models.Comment{newComment}
	user.Comments = append(comment)

    a.DB.Save(&user)
	c.JSON(http.StatusOK, gin.H{"Comment created successfully": newComment})
}

// ==================================================================
// PATCH: /post/:commentid
// ==================================================================


func (a *APIEnv) UpdateComment(c *gin.Context) {
	commentId := c.Params.ByName("commentid")
	postId := c.Params.ByName("postid")
    comment := models.Comment{}

    err := a.DB.First(&comment, commentId).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": err})
		c.Abort()
		return
	}
	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusNotFound, gin.H{"Error": "Comment not found"})
		c.Abort()
		return
	}

	token := c.GetHeader("Authorization")

	user, err := utils.CheckJWTUserID(token, a.DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": err})
		c.Abort()
		return
	}

    if comment.UserID != user.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"Unauthorized": "You're not the owner of this post"})
		c.Abort()
		return
    }

    postIdUint, err := strconv.ParseUint(postId, 0, 64)
    if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": err})
		c.Abort()
		return
    }

    if comment.PostID != uint(postIdUint) {
		c.JSON(http.StatusUnauthorized, gin.H{"Unauthorized": "PostID of the comment doesn't match the postID provided by the user'"})
		c.Abort()
		return
    }

	var newComment models.Comment

	errBind := c.BindJSON(&newComment)
	if errBind != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": errBind})
		c.Abort()
		return
	}
    
    comment.Content = newComment.Content

    a.DB.Save(&comment)
    c.JSON(http.StatusOK, gin.H{"Comment updated Successfully": comment})
}
