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

	newUser.ID, err = utils.GenID(a.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while creating the user id"})
		c.Abort()
		return
	}

	a.DB.Create(&newUser)
	c.JSON(http.StatusCreated, "Created User Successfully")
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

	c.JSON(http.StatusOK, map[string]string{
		"token": token,
	})
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

	c.JSON(http.StatusOK, user)
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

	c.JSON(http.StatusOK, users)
}

// ==================================================================
// DELETE: /account
// ==================================================================

func (a *APIEnv) DeleteUser(c *gin.Context) {
	token := c.GetHeader("Authorization")

	id, err := utils.GetTokenContent(token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		c.Abort()
		return
	}

	//for some reason, in order for the code above to work, the "PREFIX" field in the bearer auth tab NEEDS to have spaces, this may be some insomnia bug but i have no ideia

	idStr := strconv.FormatUint(uint64(id), 10)

	user, exists, err := database.GetUser(idStr, a.DB)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		c.Abort()
		return
	}

	a.DB.Delete(&user)

	c.JSON(http.StatusOK, gin.H{"Success": "User deleted successfully"})
}

// ==================================================================
// PATCH: /account
// ==================================================================

func (a *APIEnv) UpdateUser(c *gin.Context) {
	token := c.GetHeader("Authorization")

	user, err := utils.CheckJWTToken(token, a.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		c.Abort()
		return
	}

	var loginDto models.LoginDTO
	var newUser models.User

	errBind := c.BindJSON(&loginDto)
	if errBind != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errBind})
		c.Abort()
		return
	}

	if err := a.DB.Where("email = ?", loginDto.Email).First(&newUser).Error; err != gorm.ErrRecordNotFound {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Credentials"})
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

	c.JSON(http.StatusOK, user)
}

// ==================================================================
// POST: /post
// ==================================================================

func (a *APIEnv) CreatePost(c *gin.Context) {
}
