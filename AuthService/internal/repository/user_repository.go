package repository

import (
	"database/sql"
	"log"
	"time"

	"AuthService/internal/models"
	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	Create(user *models.User) error
	GetByUsername(username string) (*models.User, error)
	GetByEmail(email string) (*models.User, error)
	GetByID(id int) (*models.User, error)
}

type userRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(user *models.User) error {
	// Хешируем пароль перед сохранением
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return err
	}

	query := `
		INSERT INTO users (username, email, password, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`

	log.Printf("Executing query: %s with params: username=%s, email=%s, role=%s", 
		query, user.Username, user.Email, user.Role)

	err = r.db.QueryRow(
		query,
		user.Username,
		user.Email,
		string(hashedPassword), // Сохраняем хешированный пароль
		user.Role,
		time.Now(),
		time.Now(),
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		log.Printf("Error creating user: %v", err)
		return err
	}

	return nil
}

func (r *userRepository) GetByUsername(username string) (*models.User, error) {
	query := `
		SELECT id, username, email, password, role, created_at, updated_at, deleted_at
		FROM users
		WHERE username = $1 AND deleted_at IS NULL`

	log.Printf("Executing query: %s with param: username=%s", query, username)

	user := &models.User{}
	err := r.db.QueryRow(query, username).Scan(
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
		log.Printf("Error getting user by username: %v", err)
		return nil, err
	}

	return user, nil
}

func (r *userRepository) GetByEmail(email string) (*models.User, error) {
	query := `
		SELECT id, username, email, password, role, created_at, updated_at, deleted_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL`

	log.Printf("Executing query: %s with param: email=%s", query, email)

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
		log.Printf("Error getting user by email: %v", err)
		return nil, err
	}

	return user, nil
}

func (r *userRepository) GetByID(id int) (*models.User, error) {
	query := `
		SELECT id, username, email, password, role, created_at, updated_at, deleted_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL`

	log.Printf("Executing query: %s with param: id=%d", query, id)

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
		log.Printf("Error getting user by ID: %v", err)
		return nil, err
	}

	log.Printf("Debug - User role from database: %q\n", user.Role)
	return user, nil
} 