package repository

import (
	"database/sql"
	"testing"
	"time"

	"AuthService/internal/models"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *userRepository) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	repo := NewUserRepository(db).(*userRepository)
	return db, mock, repo
}

func TestCreateUser(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	user := &models.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
		Role:     "user",
	}

	mock.ExpectQuery("INSERT INTO users").
		WithArgs(user.Username, user.Email, sqlmock.AnyArg(), user.Role).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uint(1)))

	err := repo.CreateUser(user)
	assert.NoError(t, err)
	assert.Equal(t, uint(1), user.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateUser_Error(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	user := &models.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
		Role:     "user",
	}

	mock.ExpectQuery("INSERT INTO users").
		WithArgs(user.Username, user.Email, sqlmock.AnyArg(), user.Role).
		WillReturnError(sql.ErrConnDone)

	err := repo.CreateUser(user)
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserByID(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	expectedUser := &models.User{
		ID:       1,
		Username: "testuser",
		Password: "hashedpassword",
		Role:     "user",
	}

	mock.ExpectQuery("SELECT id, username, password, role").
		WithArgs(1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "password", "role"}).
			AddRow(expectedUser.ID, expectedUser.Username, expectedUser.Password, expectedUser.Role))

	user, err := repo.GetUserByID(1)
	assert.NoError(t, err)
	assert.Equal(t, expectedUser, user)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserByID_NotFound(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	mock.ExpectQuery("SELECT id, username, password, role").
		WithArgs(1).
		WillReturnError(sql.ErrNoRows)

	user, err := repo.GetUserByID(1)
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Equal(t, "пользователь не найден", err.Error())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserByID_Error(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	mock.ExpectQuery("SELECT id, username, password, role").
		WithArgs(1).
		WillReturnError(sql.ErrConnDone)

	user, err := repo.GetUserByID(1)
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserByUsername(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	expectedUser := &models.User{
		ID:       1,
		Username: "testuser",
		Password: "hashedpassword",
		Role:     "user",
	}

	mock.ExpectQuery("SELECT id, username, password, role").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "password", "role"}).
			AddRow(expectedUser.ID, expectedUser.Username, expectedUser.Password, expectedUser.Role))

	user, err := repo.GetUserByUsername("testuser")
	assert.NoError(t, err)
	assert.Equal(t, expectedUser, user)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserByUsername_NotFound(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	mock.ExpectQuery("SELECT id, username, password, role").
		WithArgs("testuser").
		WillReturnError(sql.ErrNoRows)

	user, err := repo.GetUserByUsername("testuser")
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Equal(t, "пользователь не найден", err.Error())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserByUsername_Error(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	mock.ExpectQuery("SELECT id, username, password, role").
		WithArgs("testuser").
		WillReturnError(sql.ErrConnDone)

	user, err := repo.GetUserByUsername("testuser")
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserExists(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	exists, err := repo.UserExists("testuser")
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserExists_Error(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser").
		WillReturnError(sql.ErrConnDone)

	exists, err := repo.UserExists("testuser")
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserRole(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	mock.ExpectQuery("SELECT role").
		WithArgs(1).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("admin"))

	role, err := repo.GetUserRole(1)
	assert.NoError(t, err)
	assert.Equal(t, "admin", role)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserRole_NotFound(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	mock.ExpectQuery("SELECT role").
		WithArgs(1).
		WillReturnError(sql.ErrNoRows)

	role, err := repo.GetUserRole(1)
	assert.Error(t, err)
	assert.Empty(t, role)
	assert.Equal(t, "пользователь не найден", err.Error())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserRole_Error(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	mock.ExpectQuery("SELECT role").
		WithArgs(1).
		WillReturnError(sql.ErrConnDone)

	role, err := repo.GetUserRole(1)
	assert.Error(t, err)
	assert.Empty(t, role)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreate(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	user := &models.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
		Role:     "user",
	}

	now := time.Now()
	mock.ExpectQuery("INSERT INTO users").
		WithArgs(user.Username, user.Email, sqlmock.AnyArg(), user.Role, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(uint(1), now, now))

	err := repo.Create(user)
	assert.NoError(t, err)
	assert.Equal(t, uint(1), user.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreate_Error(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	user := &models.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
		Role:     "user",
	}

	mock.ExpectQuery("INSERT INTO users").
		WithArgs(user.Username, user.Email, sqlmock.AnyArg(), user.Role, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(sql.ErrConnDone)

	err := repo.Create(user)
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetByEmail(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	expectedUser := &models.User{
		ID:        1,
		Username:  "testuser",
		Email:     "test@example.com",
		Password:  "hashedpassword",
		Role:      "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mock.ExpectQuery("SELECT id, username, email, password, role, created_at, updated_at, deleted_at").
		WithArgs("test@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "role", "created_at", "updated_at", "deleted_at"}).
			AddRow(expectedUser.ID, expectedUser.Username, expectedUser.Email, expectedUser.Password, expectedUser.Role, expectedUser.CreatedAt, expectedUser.UpdatedAt, nil))

	user, err := repo.GetByEmail("test@example.com")
	assert.NoError(t, err)
	assert.Equal(t, expectedUser.ID, user.ID)
	assert.Equal(t, expectedUser.Username, user.Username)
	assert.Equal(t, expectedUser.Email, user.Email)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetByEmail_Error(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	mock.ExpectQuery("SELECT id, username, email, password, role, created_at, updated_at, deleted_at").
		WithArgs("test@example.com").
		WillReturnError(sql.ErrConnDone)

	user, err := repo.GetByEmail("test@example.com")
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetByID(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	expectedUser := &models.User{
		ID:        1,
		Username:  "testuser",
		Email:     "test@example.com",
		Password:  "hashedpassword",
		Role:      "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mock.ExpectQuery("SELECT id, username, email, password, role, created_at, updated_at, deleted_at").
		WithArgs(1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "role", "created_at", "updated_at", "deleted_at"}).
			AddRow(expectedUser.ID, expectedUser.Username, expectedUser.Email, expectedUser.Password, expectedUser.Role, expectedUser.CreatedAt, expectedUser.UpdatedAt, nil))

	user, err := repo.GetByID(1)
	assert.NoError(t, err)
	assert.Equal(t, expectedUser.ID, user.ID)
	assert.Equal(t, expectedUser.Username, user.Username)
	assert.Equal(t, expectedUser.Email, user.Email)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetByID_Error(t *testing.T) {
	db, mock, repo := setupTestDB(t)
	defer db.Close()

	mock.ExpectQuery("SELECT id, username, email, password, role, created_at, updated_at, deleted_at").
		WithArgs(1).
		WillReturnError(sql.ErrConnDone)

	user, err := repo.GetByID(1)
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, mock.ExpectationsWereMet())
} 