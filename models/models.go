package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name       string `json:"name"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	Gender     string `json:"gender"`
	FollowerID *uint
	Posts      []Post
	Comments   []Comment
	Followers  []Follow
	Following  []Follow
	Likes      []Like
}

type Follow struct {
	gorm.Model
	UserID     uint
	FollowerID uint
}

type Post struct {
	gorm.Model
	UserID   uint
	Title    string `json:"title"`
	Content  string `json:"description"`
	Comments []Comment
	Likes    []Like
}

type Comment struct {
	gorm.Model
	UserID  uint
	PostID  uint
	Content string `json:"content"`
	Likes   []Like
}

type Like struct {
	gorm.Model
	UserID    uint
	PostID    uint
	CommentID uint
}

type LoginDTO struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Gender   string `json:"gender"`
}
