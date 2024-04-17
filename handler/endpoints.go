package handler

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/SawitProRecruitment/UserService/generated"
	"github.com/SawitProRecruitment/UserService/repository"
	"github.com/labstack/echo/v4"
)

// (POST /register)
func (s *Server) Register(ctx echo.Context) error {
	var body generated.RegisterJSONRequestBody
	err := ctx.Bind(&body)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{Message: "invalid request body"})
	}

	errList := s.validateRegisterRequest(body)
	if len(errList) > 0 {
		errorResp := generated.MultiErrorResponse{Message: "invallid request body", Errors: make([]generated.ErrorResponse, len(errList))}
		for i := 0; i < len(errList); i++ {
			errorResp.Errors[i] = generated.ErrorResponse{Message: errList[i].Error()}
		}
		return ctx.JSON(http.StatusBadRequest, errorResp)
	}

	existingUser, err := s.Repository.GetUserByPhoneNumber(ctx.Request().Context(), body.PhoneNumber)
	if err != nil && err != repository.ErrUserNotFound {
		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{Message: err.Error()})
	}

	if existingUser != nil {
		return ctx.JSON(http.StatusConflict, generated.ErrorResponse{Message: "phone number already exists"})
	}

	output, err := s.Repository.RegisterUser(ctx.Request().Context(), repository.RegisterUserInput{
		FullName:    body.FullName,
		PhoneNumber: body.PhoneNumber,
		Password:    body.Password,
	})
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{Message: err.Error()})
	}

	resp := generated.User{
		FullName:    output.FullName,
		Id:          output.Id,
		PhoneNumber: output.PhoneNumber,
	}
	return ctx.JSON(http.StatusCreated, resp)
}

// (POST /login)
func (s *Server) Login(ctx echo.Context) error {
	var body generated.LoginJSONRequestBody
	err := ctx.Bind(&body)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{Message: "invalid request body"})
	}

	errList := s.validateLoginRequest(body)
	if len(errList) > 0 {
		errorResp := generated.MultiErrorResponse{Message: "invalid request body", Errors: make([]generated.ErrorResponse, len(errList))}
		for i := 0; i < len(errList); i++ {
			errorResp.Errors[i] = generated.ErrorResponse{Message: errList[i].Error()}
		}
		return ctx.JSON(http.StatusBadRequest, errorResp)
	}

	user, err := s.Repository.GetUserByPhoneNumber(ctx.Request().Context(), body.PhoneNumber)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{Message: "phone number is not registered"})
		}

		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{Message: err.Error()})
	}

	err = verifyPassword(body.Password+string(user.PasswordSalt), string(user.HashedPassword))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{Message: "invalid password or phoneNumber"})
	}

	token, err := s.generateJWTToken(user)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{Message: "error generating token"})
	}

	resp := generated.LoginResponse{
		Id:          user.Id,
		AccessToken: token,
	}

	return ctx.JSON(http.StatusOK, resp)
}

// (GET /profile)
func (s *Server) GetMyProfile(ctx echo.Context) error {
	claims, err := s.verifyJWTToken(ctx.Request().Header.Get("Authorization"))
	if err != nil {
		return ctx.JSON(http.StatusForbidden, generated.ErrorResponse{Message: err.Error()})
	}

	user, err := s.Repository.GetUserById(ctx.Request().Context(), claims.UserId)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return ctx.JSON(http.StatusNotFound, generated.ErrorResponse{Message: "user not found"})
		}

		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{Message: err.Error()})
	}

	resp := generated.User{
		FullName:    user.FullName,
		Id:          user.Id,
		PhoneNumber: user.PhoneNumber,
	}
	return ctx.JSON(http.StatusOK, resp)
}

// (PATCH /profile)
func (s *Server) UpdateMyProfile(ctx echo.Context) error {
	claims, err := s.verifyJWTToken(ctx.Request().Header.Get("Authorization"))
	if err != nil {
		return ctx.JSON(http.StatusForbidden, generated.ErrorResponse{Message: err.Error()})
	}

	var body generated.UpdateMyProfileJSONRequestBody
	err = ctx.Bind(&body)
	if err != nil {
		fmt.Println(err)
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{})
	}

	if body.PhoneNumber != "" {
		user, err := s.Repository.GetUserByPhoneNumber(ctx.Request().Context(), body.PhoneNumber)
		if err != nil && err != repository.ErrUserNotFound {
			return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{Message: err.Error()})
		}

		if user != nil {
			return ctx.JSON(http.StatusConflict, generated.ErrorResponse{Message: "phone number already exists"})
		}
	}

	user, err := s.Repository.GetUserById(ctx.Request().Context(), claims.UserId)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return ctx.JSON(http.StatusNotFound, generated.ErrorResponse{Message: "user not found"})
		}

		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{Message: err.Error()})
	}
	if body.PhoneNumber != "" {
		user.PhoneNumber = body.PhoneNumber
	}
	if body.FullName != "" {
		user.FullName = body.FullName
	}

	err = s.Repository.UpdateUser(ctx.Request().Context(), user)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{Message: err.Error()})
	}

	resp := generated.User{
		FullName:    user.FullName,
		Id:          user.Id,
		PhoneNumber: user.PhoneNumber,
	}
	return ctx.JSON(http.StatusOK, resp)
}

func (s *Server) validateRegisterRequest(body generated.RegisterJSONRequestBody) []error {
	var errorList []error

	if body.FullName == "" {
		errorList = append(errorList, errors.New("fullName is required"))
	} else {
		if len(body.FullName) < 3 || len(body.FullName) > 60 {
			errorList = append(errorList, errors.New("fullName length should be between 3 and 60"))
		}
	}

	if body.PhoneNumber == "" {
		errorList = append(errorList, errors.New("phoneNumber is required"))
	} else {
		if len(body.PhoneNumber) < 10 || len(body.PhoneNumber) > 13 {
			errorList = append(errorList, errors.New("phoneNumber length should be between 10 and 13"))
		}

		regex := `^\+62\d+$`
		matched, _ := regexp.MatchString(regex, body.PhoneNumber)
		if !matched {
			errorList = append(errorList, errors.New("phoneNumber should start with +62"))
		}
	}

	if body.Password == "" {
		errorList = append(errorList, errors.New("password is required"))
	} else {
		if len(body.Password) < 6 || len(body.Password) > 64 {
			errorList = append(errorList, errors.New("password length should be between 10 and 13"))
		}

		if !isValidPassword(body.Password) {
			errorList = append(errorList, errors.New("password should contains at least 1 capital characters AND 1 number AND 1 special (non alpha-numeric) characters"))
		}
	}

	return errorList
}

func (s *Server) validateLoginRequest(body generated.LoginJSONRequestBody) []error {
	var errorList []error

	if body.PhoneNumber == "" {
		errorList = append(errorList, errors.New("phoneNumber is required"))
	}

	if body.Password == "" {
		errorList = append(errorList, errors.New("password is required"))
	}

	return errorList
}
