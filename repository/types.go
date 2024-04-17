// This file contains types that are used in the repository layer.
package repository

import (
	"errors"
	"time"
)

type GetTestByIdInput struct {
	Id string
}

type GetTestByIdOutput struct {
	Name string
}

type RegisterUserInput struct {
	FullName    string
	PhoneNumber string
	Password    string
}

type RegisterUserOutput struct {
	Id          int64
	FullName    string
	PhoneNumber string
}

type User struct {
	Id             int64
	FullName       string
	PhoneNumber    string
	HashedPassword []byte
	PasswordSalt   []byte
	LoginCount     int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

var UserNotFoundErr = errors.New("user not found")
