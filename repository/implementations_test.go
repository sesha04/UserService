package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/SawitProRecruitment/UserService/mock"
	"github.com/SawitProRecruitment/UserService/repository"
	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestRegisterUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	db, dbmock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		return
	}
	mockPassHasher := mock.NewMockPasswordHasherInterface(ctrl)
	repo := repository.Repository{
		Db:             db,
		PasswordHasher: mockPassHasher,
	}
	input := repository.RegisterUserInput{
		FullName:    "sesha",
		Password:    "Pass@123",
		PhoneNumber: "+628123456789",
	}
	timeNow := time.Now()
	salt := []byte("salt")
	hashPass := []byte("hashPass")
	user := repository.User{
		Id:             1,
		FullName:       "sesha",
		PhoneNumber:    "+628123456789",
		PasswordSalt:   []byte(salt),
		HashedPassword: []byte(hashPass),
		CreatedAt:      timeNow,
		UpdatedAt:      timeNow,
	}
	columns := []string{"id", "created_at", "updated_at"}
	t.Run("success", func(t *testing.T) {
		ctx := context.Background()
		row := sqlmock.NewRows(columns)
		row.AddRow(user.Id, timeNow, timeNow)

		mockPassHasher.EXPECT().HashAndSaltPassword(input.Password).Return(hashPass, salt, nil)
		dbmock.ExpectQuery("INSERT INTO users(full_name, phone_number, password_hash, password_salt) VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at").
			WithArgs(input.FullName, input.PhoneNumber, hashPass, salt).WillReturnRows(row)

		output, err := repo.RegisterUser(ctx, input)
		assert.Nil(t, err)
		assert.Equal(t, &user, output)
	})

	t.Run("error hashing password", func(t *testing.T) {
		ctx := context.Background()
		expectedErr := errors.New("unexpected error")

		mockPassHasher.EXPECT().HashAndSaltPassword(input.Password).Return(nil, nil, expectedErr)

		output, err := repo.RegisterUser(ctx, input)
		assert.ErrorIs(t, expectedErr, err)
		assert.Nil(t, output)
	})

	t.Run("error scanning row", func(t *testing.T) {
		ctx := context.Background()
		row := sqlmock.NewRows(columns)
		row.AddRow("user.Id", timeNow, timeNow)

		mockPassHasher.EXPECT().HashAndSaltPassword(input.Password).Return(hashPass, salt, nil)
		dbmock.ExpectQuery("INSERT INTO users(full_name, phone_number, password_hash, password_salt) VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at").
			WithArgs(input.FullName, input.PhoneNumber, hashPass, salt).WillReturnRows(row)

		output, err := repo.RegisterUser(ctx, input)
		assert.Error(t, err)
		assert.Nil(t, output)
	})
}

func TestGetUserByPhoneNumber(t *testing.T) {
	db, dbmock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		return
	}
	repo := repository.Repository{
		Db: db,
	}
	phoneNumber := "+628123456789"
	user := repository.User{
		Id:             1,
		FullName:       "sesha",
		PhoneNumber:    phoneNumber,
		PasswordSalt:   []byte("salt"),
		HashedPassword: []byte("hashPass"),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	query := "SELECT id, full_name, phone_number, password_hash, password_salt, login_count, created_at, updated_at FROM users where phone_number = $1"
	columns := []string{"id", "full_name", "phone_number", "password_hash", "password_salt", "login_count", "created_at", "updated_at"}
	t.Run("success", func(t *testing.T) {
		ctx := context.Background()
		row := sqlmock.NewRows(columns)
		row.AddRow(user.Id, user.FullName, user.PhoneNumber, user.HashedPassword, user.PasswordSalt, user.LoginCount, user.CreatedAt, user.UpdatedAt)

		dbmock.ExpectQuery(query).
			WithArgs(phoneNumber).WillReturnRows(row)

		output, err := repo.GetUserByPhoneNumber(ctx, phoneNumber)
		assert.Nil(t, err)
		assert.Equal(t, &user, output)
	})

	t.Run("error scanning row", func(t *testing.T) {
		ctx := context.Background()
		row := sqlmock.NewRows(columns)
		row.AddRow("user.Id", user.FullName, user.PhoneNumber, user.HashedPassword, user.PasswordSalt, user.LoginCount, user.CreatedAt, user.UpdatedAt)

		dbmock.ExpectQuery(query).
			WithArgs(phoneNumber).WillReturnRows(row)

		output, err := repo.GetUserByPhoneNumber(ctx, phoneNumber)
		assert.Error(t, err)
		assert.Nil(t, output)
	})

	t.Run("error row not found", func(t *testing.T) {
		ctx := context.Background()

		dbmock.ExpectQuery(query).
			WithArgs(phoneNumber).WillReturnError(sql.ErrNoRows)

		output, err := repo.GetUserByPhoneNumber(ctx, phoneNumber)
		assert.ErrorIs(t, repository.ErrUserNotFound, err)
		assert.Nil(t, output)
	})
}

func TestGetUserById(t *testing.T) {
	db, dbmock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		return
	}
	repo := repository.Repository{
		Db: db,
	}
	id := int64(43)
	user := repository.User{
		Id:             id,
		FullName:       "sesha",
		PhoneNumber:    "+62123456789",
		PasswordSalt:   []byte("salt"),
		HashedPassword: []byte("hashPass"),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	query := "SELECT id, full_name, phone_number, password_hash, password_salt, login_count, created_at, updated_at FROM users where id = $1"
	columns := []string{"id", "full_name", "phone_number", "password_hash", "password_salt", "login_count", "created_at", "updated_at"}
	t.Run("success", func(t *testing.T) {
		ctx := context.Background()
		row := sqlmock.NewRows(columns)
		row.AddRow(user.Id, user.FullName, user.PhoneNumber, user.HashedPassword, user.PasswordSalt, user.LoginCount, user.CreatedAt, user.UpdatedAt)

		dbmock.ExpectQuery(query).
			WithArgs(id).WillReturnRows(row)

		output, err := repo.GetUserById(ctx, id)
		assert.Nil(t, err)
		assert.Equal(t, &user, output)
	})

	t.Run("error scanning row", func(t *testing.T) {
		ctx := context.Background()
		row := sqlmock.NewRows(columns)
		row.AddRow("user.Id", user.FullName, user.PhoneNumber, user.HashedPassword, user.PasswordSalt, user.LoginCount, user.CreatedAt, user.UpdatedAt)

		dbmock.ExpectQuery(query).
			WithArgs(id).WillReturnRows(row)

		output, err := repo.GetUserById(ctx, id)
		assert.Error(t, err)
		assert.Nil(t, output)
	})

	t.Run("error row not found", func(t *testing.T) {
		ctx := context.Background()

		dbmock.ExpectQuery(query).
			WithArgs(id).WillReturnError(sql.ErrNoRows)

		output, err := repo.GetUserById(ctx, id)
		assert.ErrorIs(t, repository.ErrUserNotFound, err)
		assert.Nil(t, output)
	})
}

func TestUpdateUser(t *testing.T) {
	db, dbmock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		return
	}
	repo := repository.Repository{
		Db: db,
	}
	user := repository.User{
		Id:             43,
		FullName:       "sesha",
		PhoneNumber:    "+62123456789",
		PasswordSalt:   []byte("salt"),
		HashedPassword: []byte("hashPass"),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	query := "UPDATE users SET phone_number = $1, full_name = $2, updated_at = NOW() WHERE id = $3 RETURNING phone_number, full_name, updated_at"
	columns := []string{"phone_number", "full_name", "updated_at"}
	t.Run("success", func(t *testing.T) {
		ctx := context.Background()
		row := sqlmock.NewRows(columns)
		row.AddRow(user.PhoneNumber, user.FullName, user.UpdatedAt)

		dbmock.ExpectQuery(query).
			WithArgs(user.PhoneNumber, user.FullName, user.Id).WillReturnRows(row)

		err := repo.UpdateUser(ctx, &user)
		assert.Nil(t, err)
	})

	t.Run("error scanning row", func(t *testing.T) {
		ctx := context.Background()
		row := sqlmock.NewRows(columns)
		row.AddRow(user.PhoneNumber, user.FullName, "user.UpdatedAt")

		dbmock.ExpectQuery(query).
			WithArgs(user.PhoneNumber, user.FullName, user.Id).WillReturnRows(row)

		err := repo.UpdateUser(ctx, &user)
		assert.Error(t, err)
	})
}

func TestIncrementUserLoginCount(t *testing.T) {
	db, dbmock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		return
	}
	repo := repository.Repository{
		Db: db,
	}
	id := int64(345)
	query := "UPDATE users SET login_count = login_count + 1, updated_at = NOW() WHERE id = $1"
	t.Run("success", func(t *testing.T) {
		ctx := context.Background()

		dbmock.ExpectExec(query).
			WithArgs(id).WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.IncrementUserLoginCount(ctx, id)
		assert.Nil(t, err)
	})

	t.Run("error scanning row", func(t *testing.T) {
		ctx := context.Background()
		expectedErr := errors.New("unexpected error")

		dbmock.ExpectExec(query).
			WithArgs(id).WillReturnError(expectedErr)

		err := repo.IncrementUserLoginCount(ctx, id)
		assert.ErrorIs(t, expectedErr, err)
	})
}
