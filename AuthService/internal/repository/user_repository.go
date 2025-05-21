package repository

import (
	"database/sql"
	"errors"
	"time"

	"AuthService/internal/models"
	"golang.org/x/crypto/bcrypt"
	"github.com/Luxtington/Shared/logger"
	"go.uber.org/zap"
)

type UserRepository interface {
	CreateUser(user *models.User) error
	GetUserByID(id int) (*models.User, error)
	GetUserByUsername(username string) (*models.User, error)
	UserExists(username string) (bool, error)
	GetUserRole(userID int) (string, error)
}

type userRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) CreateUser(user *models.User) error {
	log := logger.GetLogger()
	
	query := `INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id`
	
	log.Info("Executing query",
		zap.String("query", query),
		zap.String("username", user.Username),
		zap.String("email", user.Email),
		zap.String("role", user.Role))

	err := r.db.QueryRow(query, user.Username, user.Email, user.Password, user.Role).Scan(&user.ID)
	if err != nil {
		log.Error("Error creating user", zap.Error(err))
		return err
	}

	return nil
}

func (r *userRepository) GetUserByID(id int) (*models.User, error) {
	query := `
		SELECT id, username, email, password, role
		FROM users
		WHERE id = $1`

	user := &models.User{}
	err := r.db.QueryRow(query, id).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("пользователь не найден")
		}
		return nil, err
	}

	return user, nil
}

func (r *userRepository) GetUserByUsername(username string) (*models.User, error) {
	query := `
		SELECT id, username, email, password, role
		FROM users
		WHERE username = $1`

	user := &models.User{}
	err := r.db.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("пользователь не найден")
		}
		return nil, err
	}

	return user, nil
}

func (r *userRepository) UserExists(username string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM users WHERE username = $1
		)`

	var exists bool
	err := r.db.QueryRow(query, username).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *userRepository) GetUserRole(userID int) (string, error) {
	query := `
		SELECT role
		FROM users
		WHERE id = $1`

	var role string
	err := r.db.QueryRow(query, userID).Scan(&role)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("пользователь не найден")
		}
		return "", err
	}

	return role, nil
}

func (r *userRepository) Create(user *models.User) error {
	log := logger.GetLogger()
	
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("Error hashing password", zap.Error(err))
		return err
	}

	query := `
		INSERT INTO users (username, email, password, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`

	log.Info("Executing query",
		zap.String("query", query),
		zap.String("username", user.Username),
		zap.String("email", user.Email),
		zap.String("role", user.Role))

	err = r.db.QueryRow(
		query,
		user.Username,
		user.Email,
		string(hashedPassword),
		user.Role,
		time.Now(),
		time.Now(),
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		log.Error("Error creating user", zap.Error(err))
		return err
	}

	return nil
}

func (r *userRepository) GetByEmail(email string) (*models.User, error) {
	log := logger.GetLogger()
	
	query := `
		SELECT id, username, email, password, role, created_at, updated_at, deleted_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL`

	log.Info("Executing query",
		zap.String("query", query),
		zap.String("email", email))

	user := &models.User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)

	if err != nil {
		log.Error("Error getting user by email", zap.Error(err))
		return nil, err
	}

	return user, nil
}

func (r *userRepository) GetByID(id int) (*models.User, error) {
	log := logger.GetLogger()
	
	query := `
		SELECT id, username, email, password, role, created_at, updated_at, deleted_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL`

	log.Info("Executing query",
		zap.String("query", query),
		zap.Int("id", id))

	user := &models.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)

	if err != nil {
		log.Error("Error getting user by ID", zap.Error(err))
		return nil, err
	}

	log.Info("User role from database", zap.String("role", user.Role))
	return user, nil
} 