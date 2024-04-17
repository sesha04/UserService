// Code generated by MockGen. DO NOT EDIT.
// Source: repository/interfaces.go

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	repository "github.com/SawitProRecruitment/UserService/repository"
	gomock "github.com/golang/mock/gomock"
)

// MockRepositoryInterface is a mock of RepositoryInterface interface.
type MockRepositoryInterface struct {
	ctrl     *gomock.Controller
	recorder *MockRepositoryInterfaceMockRecorder
}

// MockRepositoryInterfaceMockRecorder is the mock recorder for MockRepositoryInterface.
type MockRepositoryInterfaceMockRecorder struct {
	mock *MockRepositoryInterface
}

// NewMockRepositoryInterface creates a new mock instance.
func NewMockRepositoryInterface(ctrl *gomock.Controller) *MockRepositoryInterface {
	mock := &MockRepositoryInterface{ctrl: ctrl}
	mock.recorder = &MockRepositoryInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRepositoryInterface) EXPECT() *MockRepositoryInterfaceMockRecorder {
	return m.recorder
}

// GetUserById mocks base method.
func (m *MockRepositoryInterface) GetUserById(ctx context.Context, id int64) (*repository.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserById", ctx, id)
	ret0, _ := ret[0].(*repository.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserById indicates an expected call of GetUserById.
func (mr *MockRepositoryInterfaceMockRecorder) GetUserById(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserById", reflect.TypeOf((*MockRepositoryInterface)(nil).GetUserById), ctx, id)
}

// GetUserByPhoneNumber mocks base method.
func (m *MockRepositoryInterface) GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*repository.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByPhoneNumber", ctx, phoneNumber)
	ret0, _ := ret[0].(*repository.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByPhoneNumber indicates an expected call of GetUserByPhoneNumber.
func (mr *MockRepositoryInterfaceMockRecorder) GetUserByPhoneNumber(ctx, phoneNumber interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByPhoneNumber", reflect.TypeOf((*MockRepositoryInterface)(nil).GetUserByPhoneNumber), ctx, phoneNumber)
}

// IncrementUserLoginCount mocks base method.
func (m *MockRepositoryInterface) IncrementUserLoginCount(ctx context.Context, id int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IncrementUserLoginCount", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// IncrementUserLoginCount indicates an expected call of IncrementUserLoginCount.
func (mr *MockRepositoryInterfaceMockRecorder) IncrementUserLoginCount(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IncrementUserLoginCount", reflect.TypeOf((*MockRepositoryInterface)(nil).IncrementUserLoginCount), ctx, id)
}

// RegisterUser mocks base method.
func (m *MockRepositoryInterface) RegisterUser(ctx context.Context, input repository.RegisterUserInput) (*repository.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterUser", ctx, input)
	ret0, _ := ret[0].(*repository.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RegisterUser indicates an expected call of RegisterUser.
func (mr *MockRepositoryInterfaceMockRecorder) RegisterUser(ctx, input interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterUser", reflect.TypeOf((*MockRepositoryInterface)(nil).RegisterUser), ctx, input)
}

// UpdateUser mocks base method.
func (m *MockRepositoryInterface) UpdateUser(ctx context.Context, input *repository.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUser", ctx, input)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *MockRepositoryInterfaceMockRecorder) UpdateUser(ctx, input interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*MockRepositoryInterface)(nil).UpdateUser), ctx, input)
}

// MockPasswordHasherInterface is a mock of PasswordHasherInterface interface.
type MockPasswordHasherInterface struct {
	ctrl     *gomock.Controller
	recorder *MockPasswordHasherInterfaceMockRecorder
}

// MockPasswordHasherInterfaceMockRecorder is the mock recorder for MockPasswordHasherInterface.
type MockPasswordHasherInterfaceMockRecorder struct {
	mock *MockPasswordHasherInterface
}

// NewMockPasswordHasherInterface creates a new mock instance.
func NewMockPasswordHasherInterface(ctrl *gomock.Controller) *MockPasswordHasherInterface {
	mock := &MockPasswordHasherInterface{ctrl: ctrl}
	mock.recorder = &MockPasswordHasherInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPasswordHasherInterface) EXPECT() *MockPasswordHasherInterfaceMockRecorder {
	return m.recorder
}

// HashAndSaltPassword mocks base method.
func (m *MockPasswordHasherInterface) HashAndSaltPassword(password string) ([]byte, []byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HashAndSaltPassword", password)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].([]byte)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// HashAndSaltPassword indicates an expected call of HashAndSaltPassword.
func (mr *MockPasswordHasherInterfaceMockRecorder) HashAndSaltPassword(password interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HashAndSaltPassword", reflect.TypeOf((*MockPasswordHasherInterface)(nil).HashAndSaltPassword), password)
}