package handler

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/SawitProRecruitment/UserService/repository"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

type JWTClaims struct {
	UserId int64
	jwt.StandardClaims
}

func (c JWTClaims) Valid() error {
	return c.StandardClaims.Valid()
}

type Server struct {
	Repository repository.RepositoryInterface
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

type NewServerOptions struct {
	Repository repository.RepositoryInterface
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func NewServer(opts NewServerOptions) *Server {
	return &Server{
		Repository: opts.Repository,
		privateKey: opts.PrivateKey,
		publicKey:  opts.PublicKey,
	}
}

func isValidPassword(password string) bool {
	hasCapital := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(password)

	return hasCapital && hasNumber && hasSpecial
}

func verifyPassword(password, hashedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) generateJWTToken(user *repository.User) (string, error) {
	claims := JWTClaims{UserId: user.Id, StandardClaims: jwt.StandardClaims{ExpiresAt: time.Now().Add(time.Hour * 24).Unix()}}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *Server) verifyJWTToken(auth string) (JWTClaims, error) {
	splitAuth := strings.Split(auth, "Bearer ")
	if len(splitAuth) < 2 {
		return JWTClaims{}, ErrUnauthorized
	}

	tokenString := splitAuth[1]
	claims := JWTClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return s.publicKey, nil
	})

	if err != nil || !parsedToken.Valid {
		return JWTClaims{}, ErrForbidden
	}

	return claims, nil
}
