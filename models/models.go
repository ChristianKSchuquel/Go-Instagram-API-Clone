package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name      string `json:"name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Gender    string `json:"gender"`
	Posts     []Post
	Comments  []Comment
	Followers []User
}

type Post struct {
	gorm.Model
	Owner       User
	Title       string `json:"title"`
	Description string `json:"description"`
	Image       string `json:"image"`
	Comments    []Comment
}

type Comment struct {
	gorm.Model
	Commenter User
	Post      Post
	Content   string `json:"content"`
	Likes     []User
}

type LoginDTO struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Gender   string `json:"gender"`
}
