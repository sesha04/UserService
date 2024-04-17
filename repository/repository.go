// This file contains the repository implementation layer.
package repository

import (
	"crypto/rand"
	"database/sql"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Repository struct {
	Db *sql.DB
}

type NewRepositoryOptions struct {
	Dsn string
}

func NewRepository(opts NewRepositoryOptions) *Repository {
	db, err := sql.Open("postgres", opts.Dsn)
	if err != nil {
		panic(err)
	}
	return &Repository{
		Db: db,
	}
}

func hashAndSalt(password string) ([]byte, []byte, error) {
	// Generate a random salt with 16 bytes
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, nil, err
	}

	// Hash the password with the salt using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password+string(salt)), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}

	return hashedPassword, salt, nil
}
