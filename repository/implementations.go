package repository

import (
	"context"
	"database/sql"
)

func (r *Repository) RegisterUser(ctx context.Context, input RegisterUserInput) (*User, error) {
	hashed, salt, err := hashAndSalt(input.Password)
	if err != nil {
		return nil, err
	}

	res := r.Db.QueryRowContext(ctx,
		"INSERT INTO users(full_name, phone_number, password_hash, password_salt) VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at",
		input.FullName, input.PhoneNumber, hashed, salt)

	output := User{
		FullName:       input.FullName,
		PhoneNumber:    input.PhoneNumber,
		HashedPassword: hashed,
		PasswordSalt:   salt,
	}

	err = res.Scan(&output.Id, &output.CreatedAt, &output.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return &output, nil
}

func (r *Repository) GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*User, error) {
	res := r.Db.QueryRowContext(ctx,
		"SELECT id, full_name, phone_number, password_hash, password_salt, login_count, created_at, updated_at FROM users where phone_number = $1",
		phoneNumber)
	output := User{}
	err := res.Scan(&output.Id, &output.FullName, &output.PhoneNumber,
		&output.HashedPassword, &output.PasswordSalt, &output.LoginCount, &output.CreatedAt, &output.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}

		return nil, err
	}

	return &output, nil
}

func (r *Repository) GetUserById(ctx context.Context, id int64) (*User, error) {
	res := r.Db.QueryRowContext(ctx,
		"SELECT id, full_name, phone_number, password_hash, password_salt, login_count, created_at, updated_at FROM users where id = $1",
		id)
	output := User{}
	err := res.Scan(&output.Id, &output.FullName, &output.PhoneNumber,
		&output.HashedPassword, &output.PasswordSalt, &output.LoginCount, &output.CreatedAt, &output.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}

		return nil, err
	}

	return &output, nil
}

func (r *Repository) UpdateUser(ctx context.Context, input *User) error {
	res := r.Db.QueryRowContext(ctx,
		"UPDATE users SET phone_number = $1, full_name = $2, updated_at = NOW() WHERE id = $3 RETURNING phone_number, full_name, updated_at",
		input.PhoneNumber, input.FullName, input.Id)

	err := res.Scan(&input.PhoneNumber, &input.FullName, &input.UpdatedAt)
	if err != nil {
		return err
	}

	return nil
}
