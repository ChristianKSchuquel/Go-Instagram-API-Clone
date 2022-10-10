package database

import (
	"api2/models"
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func GetEnvVar(key string) string {
	err := godotenv.Load(".env")
	if err != nil {
		log.Println("Error while loading .env file")
	}

	return os.Getenv(key)
}

func Setup() {
	dsn := GetEnvVar("DSN")
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Println("Error:", err.Error())
		return
	}

	db.AutoMigrate(&models.Comment{})
	db.AutoMigrate(&models.Post{})
	db.AutoMigrate(&models.User{})
	db.AutoMigrate(&models.Comment{})
	db.AutoMigrate(&models.Like{})
	db.AutoMigrate(&models.Follow{})

	DB = db
	return
}

func GetDB() *gorm.DB {
	return DB
}

var User models.User

func GetUser(id string, db *gorm.DB) (models.User, bool, error) {
	u := models.User{}

	err := db.First(&u, id).Error

	if err != nil && err != gorm.ErrRecordNotFound {
		return u, false, err
	}

	if err == gorm.ErrRecordNotFound {
		return u, false, nil
	}

	return u, true, nil
}

func GetAllUsers(db *gorm.DB) ([]models.User, bool, error) {
	users := []models.User{}

	result := db.Find(&users)
	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return users, false, result.Error
	}

	if result.Error == gorm.ErrRecordNotFound {
		return users, false, nil
	}

	return users, true, nil
}
