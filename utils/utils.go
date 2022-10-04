package utils

import (
	"api2/database"
	"errors"
	"log"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt"
)

// validates a password, used in signup to verify the user provided password

func ValidatePwd(s string) bool {
	var (
		hasMinLen  = false
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	if len(s) >= 7 {
		hasMinLen = true
	}
	for _, char := range s {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	return hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
}

type JWTClaim struct {
	Id uint
	jwt.StandardClaims
}

var jwt_secret = database.GetEnvVar("JWT_SECRET")

// generate a JWT token with the user id to be used in login and auth

func GenToken(userId uint) (string, error) {
	expTime := time.Now().Add(1 * time.Hour)
	claims := &JWTClaim{
		Id: userId,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expTime.Unix(),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	token, err := t.SignedString([]byte(jwt_secret))
	if err != nil {
		log.Println("error in t.signedstring:", err)
		return "Error:", err
	}
	return token, nil
}

// validates a JWT token, to be used in checking if the users is logged in secured routes

func ValidateToken(signedToken string) (err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(jwt_secret), nil
		},
	)
	if err != nil {
		return
	}
	claims, ok := token.Claims.(*JWTClaim)
	if !ok {
		err = errors.New("couldnt parse claims")
		return
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		err = errors.New("token expired")
		return
	}
	return
}

func GetTokenContent(signedToken string) (id uint, err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(jwt_secret), nil
		},
	)
	if err != nil {
		return
	}

	claims := token.Claims.(*JWTClaim)
	return claims.Id, nil
}
