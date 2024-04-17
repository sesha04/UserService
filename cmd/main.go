package main

import (
	"fmt"
	"os"

	"github.com/SawitProRecruitment/UserService/generated"
	"github.com/SawitProRecruitment/UserService/handler"
	"github.com/SawitProRecruitment/UserService/repository"
	"github.com/golang-jwt/jwt"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	var server generated.ServerInterface = newServer()

	generated.RegisterHandlers(e, server)
	e.Logger.Fatal(e.Start(":1323"))
}

func newServer() *handler.Server {
	dbDsn := os.Getenv("DATABASE_URL")
	var repo repository.RepositoryInterface = repository.NewRepository(repository.NewRepositoryOptions{
		Dsn: dbDsn,
	})

	privateKeyString := os.Getenv("PRIVATE_KEY")

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyString))
	if err != nil {
		panic(fmt.Sprint("Error parsing private key:", err))
	}

	publicKeyString := os.Getenv("PUBLIC_KEY")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyString))
	if err != nil {
		panic(fmt.Sprint("Error parsing public key:", err))
	}

	opts := handler.NewServerOptions{
		Repository: repo,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
	return handler.NewServer(opts)
}
