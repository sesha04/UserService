// This file contains the interfaces for the repository layer.
// The repository layer is responsible for interacting with the database.
// For testing purpose we will generate mock implementations of these
// interfaces using mockgen. See the Makefile for more information.
package repository

import "context"

type RepositoryInterface interface {
	RegisterUser(ctx context.Context, input RegisterUserInput) (*User, error)
	GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*User, error)
	GetUserById(ctx context.Context, id int64) (*User, error)
	UpdateUser(ctx context.Context, input *User) error
}
