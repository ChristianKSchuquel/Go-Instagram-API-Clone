package utils

import (
	"api2/database"
    "encoding/base64"
	"api2/models"
	"errors"
	"log"
    "fmt"
	"math/rand"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt"
	"gorm.io/gorm"
)

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

func GenID [Model models.Comment | models.Post | models.User](db *gorm.DB, model Model) (id uint) {
	randomId := rand.Uint32()
	if err := db.First(&model, randomId).Error; err != gorm.ErrRecordNotFound {
		return GenID(db, model)
	}

	return uint(randomId)
}

type JWTClaim struct {
	Id uint
	jwt.StandardClaims
}

var jwt_secret = database.GetEnvVar("JWT_SECRET")

func GenToken(duration int, payload interface{}, privateKey string) (string, error) {
    decodedPrivateKey, err := base64.StdEncoding.DecodeString(privateKey)
    if err != nil {
        return "", fmt.Errorf("could not decode: %w", err)
    }

    key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)

	if err != nil {
        return "", fmt.Errorf("validate: parse key: %w", err)
	}

    nanosecondsToMinutes := 60000000000

    var tokenDuration time.Duration = time.Duration(duration) * time.Duration(nanosecondsToMinutes)
    log.Println(tokenDuration)

    now := time.Now().UTC()

    claims := make(jwt.MapClaims)
    claims["sub"] = payload
    claims["exp"] = now.Add(tokenDuration).Unix()
    claims["iat"] = now.Unix()
    claims["nbf"] = now.Unix()

    token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
    if err != nil {
        return "", fmt.Errorf("Error: could not generate token: %w", err)
    }

	return token, nil
}

func ValidateToken(token string, publicKey string) (interface{}, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)
	if err != nil {
		return "", fmt.Errorf("validate: parse key: %w", err)
	}
    log.Println("1")

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
		}
		return key, nil
	})
    log.Println("2")

	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
    log.Println("3")

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("validate: invalid token")
	}

	return claims["sub"], nil
}

// gets the id from the jwt token and checks if it is valid

func GetUserByJWT(token string, db *gorm.DB, publicKey string) (user models.User, err error) {
    log.Println(token)
	sub, err := ValidateToken(token, publicKey)
	if err != nil {
		return models.User{}, errors.New("Could not validate token")
	}

    log.Println("2")
	user, exists, err := database.GetUser(fmt.Sprint(sub), db)
	if err != nil {
		log.Println(err)
		return user, err
	}

    log.Println("3")
	if !exists {
		return user, errors.New("User not found")
	}

	return user, nil
}
