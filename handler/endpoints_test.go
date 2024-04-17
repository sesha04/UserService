package handler_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SawitProRecruitment/UserService/generated"
	"github.com/SawitProRecruitment/UserService/handler"
	"github.com/SawitProRecruitment/UserService/mock"
	"github.com/SawitProRecruitment/UserService/repository"
	"github.com/golang-jwt/jwt"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestRegister(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey

	repo := mock.NewMockRepositoryInterface(ctrl)
	server := handler.NewServer(handler.NewServerOptions{
		Repository: repo,
		PrivateKey: privateKey,
		PublicKey:  &publicKey,
	})
	e := echo.New()
	input := repository.RegisterUserInput{
		FullName:    "sesha",
		Password:    "Pass@123",
		PhoneNumber: "+628123456789",
	}
	user := repository.User{
		Id:          1,
		FullName:    input.FullName,
		PhoneNumber: input.PhoneNumber,
	}
	reqBody := fmt.Sprintf(`{
		"fullName" : "%s",
		"password" : "%s",
		"phoneNumber" : "%s"
	}`, input.FullName, input.Password, input.PhoneNumber)

	t.Run("success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), input.PhoneNumber).Return(nil, repository.ErrUserNotFound)
		repo.EXPECT().RegisterUser(req.Context(), input).Return(&user, nil)

		err := server.Register(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusCreated, rec.Code)
		resp := generated.User{}
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.Nil(t, err)
		assert.Equal(t, generated.User{
			Id:          user.Id,
			FullName:    user.FullName,
			PhoneNumber: user.PhoneNumber,
		}, resp)
	})

	t.Run("error invalid field in request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
			"full_name" : "name",
		}`))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		err := server.Register(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("error empty request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		err := server.Register(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("error invalid request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
			"fullName" : "s",
			"password" : "s",
			"phoneNumber" : "+63"
		}`))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		err := server.Register(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("error getting user by phone number", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), input.PhoneNumber).Return(nil, errors.New("unexpected error"))

		err := server.Register(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("error phone number already registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), input.PhoneNumber).Return(&user, nil)

		err := server.Register(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusConflict, rec.Code)
	})

	t.Run("error storing user to database", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), input.PhoneNumber).Return(nil, repository.ErrUserNotFound)
		repo.EXPECT().RegisterUser(req.Context(), input).Return(nil, errors.New("unexpected error"))

		err := server.Register(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey

	repo := mock.NewMockRepositoryInterface(ctrl)
	server := handler.NewServer(handler.NewServerOptions{
		Repository: repo,
		PrivateKey: privateKey,
		PublicKey:  &publicKey,
	})
	e := echo.New()
	password := "Pass@123"
	phoneNumber := "+628123456789"
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password+string(salt)), bcrypt.DefaultCost)
	user := repository.User{
		Id:             1,
		FullName:       "sesha",
		PhoneNumber:    phoneNumber,
		HashedPassword: hashedPassword,
		PasswordSalt:   salt,
	}
	reqBody := fmt.Sprintf(`{
		"password" : "%s",
		"phoneNumber" : "%s"
	}`, password, phoneNumber)
	claims := handler.JWTClaims{UserId: user.Id, StandardClaims: jwt.StandardClaims{ExpiresAt: time.Now().Add(time.Hour * 24).Unix()}}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	t.Run("success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), phoneNumber).Return(&user, nil)
		repo.EXPECT().IncrementUserLoginCount(req.Context(), user.Id).Return(nil)

		err := server.Login(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		resp := generated.LoginResponse{}
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.Nil(t, err)
		assert.Equal(t, generated.LoginResponse{
			Id:          user.Id,
			AccessToken: tokenString,
		}, resp)
	})

	t.Run("error invalid field in request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
			"full_name" : "name",
		}`))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		err := server.Login(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("error empty request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		err := server.Login(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("error getting user by phone number", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), phoneNumber).Return(nil, errors.New("unexpected error"))

		err := server.Login(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("error phone number not registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), phoneNumber).Return(nil, repository.ErrUserNotFound)

		err := server.Login(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("error wrong password", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(fmt.Sprintf(`{
			"password" : "wrongPassword@321",
			"phoneNumber" : "%s"
		}`, phoneNumber)))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), phoneNumber).Return(&user, nil)

		err := server.Login(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("error generating token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), phoneNumber).Return(&user, nil)

		invalidPrivKey, _ := rsa.GenerateKey(strings.NewReader("random bytes."), 13)
		server := handler.NewServer(handler.NewServerOptions{
			Repository: repo,
			PrivateKey: invalidPrivKey,
		})
		err := server.Login(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("error increment login count", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), phoneNumber).Return(&user, nil)
		repo.EXPECT().IncrementUserLoginCount(req.Context(), user.Id).Return(errors.New("unexpected error"))

		err := server.Login(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestGetProfile(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey

	repo := mock.NewMockRepositoryInterface(ctrl)
	server := handler.NewServer(handler.NewServerOptions{
		Repository: repo,
		PrivateKey: privateKey,
		PublicKey:  &publicKey,
	})
	e := echo.New()
	user := repository.User{
		Id:          1,
		FullName:    "sesha",
		PhoneNumber: "+628123456789",
	}
	claims := handler.JWTClaims{UserId: user.Id, StandardClaims: jwt.StandardClaims{ExpiresAt: time.Now().Add(time.Hour * 24).Unix()}}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	t.Run("success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserById(req.Context(), user.Id).Return(&user, nil)

		err := server.GetMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		resp := generated.User{}
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.Nil(t, err)
		assert.Equal(t, generated.User{
			Id:          user.Id,
			PhoneNumber: user.PhoneNumber,
			FullName:    user.FullName,
		}, resp)
	})

	t.Run("error invalid auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Add("Authorization", tokenString)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		err := server.GetMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("error invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Add("Authorization", "Bearer invalidtoken")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		err := server.GetMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("error user not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserById(req.Context(), user.Id).Return(nil, repository.ErrUserNotFound)

		err := server.GetMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("error getting user by id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserById(req.Context(), user.Id).Return(nil, errors.New("unexpected error"))

		err := server.GetMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestUpdateProfile(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey

	repo := mock.NewMockRepositoryInterface(ctrl)
	server := handler.NewServer(handler.NewServerOptions{
		Repository: repo,
		PrivateKey: privateKey,
		PublicKey:  &publicKey,
	})
	userId := int64(1)
	e := echo.New()
	claims := handler.JWTClaims{UserId: userId, StandardClaims: jwt.StandardClaims{ExpiresAt: time.Now().Add(time.Hour * 24).Unix()}}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)
	t.Run("success update full name and phone number", func(t *testing.T) {
		user := repository.User{
			Id:          userId,
			FullName:    "sesha",
			PhoneNumber: "+628123456789",
		}
		updateName := "sesha new"
		updatePhone := "+6281234567891"
		reqBody := fmt.Sprintf(`{
			"fullName" : "%s",
			"phoneNumber" : "%s"
		}`, updateName, updatePhone)
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(reqBody))
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), updatePhone).Return(nil, repository.ErrUserNotFound)
		repo.EXPECT().GetUserById(req.Context(), user.Id).Return(&user, nil)
		repo.EXPECT().UpdateUser(req.Context(), &user).Return(nil)

		err := server.UpdateMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		resp := generated.User{}
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.Nil(t, err)
		assert.Equal(t, generated.User{
			Id:          user.Id,
			PhoneNumber: updatePhone,
			FullName:    updateName,
		}, resp)
	})

	t.Run("error invalid auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/", nil)
		req.Header.Add("Authorization", tokenString)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		err := server.UpdateMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("error invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/", nil)
		req.Header.Add("Authorization", "Bearer invalidtoken")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		err := server.UpdateMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("error invalid field in request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
			"full_name" : "name",
		}`))
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		err := server.UpdateMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("error getting user by phone number", func(t *testing.T) {
		updatePhone := "+6281234567891"
		reqBody := fmt.Sprintf(`{
			"phoneNumber" : "%s"
		}`, updatePhone)
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(reqBody))
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), updatePhone).Return(nil, errors.New("unexpected error"))

		err := server.UpdateMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("error phone number conflict", func(t *testing.T) {
		updatePhone := "+6281234567891"
		reqBody := fmt.Sprintf(`{
			"phoneNumber" : "%s"
		}`, updatePhone)
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(reqBody))
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), updatePhone).Return(&repository.User{Id: 1}, nil)

		err := server.UpdateMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusConflict, rec.Code)
	})

	t.Run("error getting user by id", func(t *testing.T) {
		updateName := "new name"
		reqBody := fmt.Sprintf(`{
			"fullName" : "%s"
		}`, updateName)
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(reqBody))
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserById(req.Context(), userId).Return(nil, errors.New("unexpected error"))

		err := server.UpdateMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("error user not found", func(t *testing.T) {
		updateName := "new name"
		reqBody := fmt.Sprintf(`{
			"fullName" : "%s"
		}`, updateName)
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(reqBody))
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserById(req.Context(), userId).Return(nil, repository.ErrUserNotFound)

		err := server.UpdateMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("error update user", func(t *testing.T) {
		user := repository.User{
			Id:          userId,
			FullName:    "sesha",
			PhoneNumber: "+628123456789",
		}
		updateName := "sesha new"
		updatePhone := "+6281234567891"
		reqBody := fmt.Sprintf(`{
			"fullName" : "%s",
			"phoneNumber" : "%s"
		}`, updateName, updatePhone)
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(reqBody))
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), updatePhone).Return(nil, repository.ErrUserNotFound)
		repo.EXPECT().GetUserById(req.Context(), user.Id).Return(&user, nil)
		repo.EXPECT().UpdateUser(req.Context(), &user).Return(errors.New("unexpected error"))

		err := server.UpdateMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("success update full name only", func(t *testing.T) {
		user := repository.User{
			Id:          userId,
			FullName:    "sesha",
			PhoneNumber: "+628123456789",
		}
		updateName := "sesha new"
		reqBody := fmt.Sprintf(`{
			"fullName" : "%s"
		}`, updateName)
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(reqBody))
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserById(req.Context(), user.Id).Return(&user, nil)
		repo.EXPECT().UpdateUser(req.Context(), &user).Return(nil)

		err := server.UpdateMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		resp := generated.User{}
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.Nil(t, err)
		assert.Equal(t, generated.User{
			Id:          user.Id,
			PhoneNumber: user.PhoneNumber,
			FullName:    updateName,
		}, resp)
	})

	t.Run("success update phone number only", func(t *testing.T) {
		user := repository.User{
			Id:          userId,
			FullName:    "sesha",
			PhoneNumber: "+628123456789",
		}
		updatePhone := "+6281234567891"
		reqBody := fmt.Sprintf(`{
			"phoneNumber" : "%s"
		}`, updatePhone)
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(reqBody))
		req.Header.Add("Authorization", fmt.Sprint("Bearer ", tokenString))
		req.Header.Add("content-type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		repo.EXPECT().GetUserByPhoneNumber(req.Context(), updatePhone).Return(nil, repository.ErrUserNotFound)
		repo.EXPECT().GetUserById(req.Context(), user.Id).Return(&user, nil)
		repo.EXPECT().UpdateUser(req.Context(), &user).Return(nil)

		err := server.UpdateMyProfile(ctx)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		resp := generated.User{}
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.Nil(t, err)
		assert.Equal(t, generated.User{
			Id:          user.Id,
			PhoneNumber: updatePhone,
			FullName:    user.FullName,
		}, resp)
	})
}
