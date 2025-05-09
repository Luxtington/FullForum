package repository

import (
    "database/sql"
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
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash), bcrypt.DefaultCost)
    if err != nil {
        return err
    }

    query := `
        INSERT INTO users (username, email, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id, created_at
    `
    
    return r.db.QueryRow(query, user.Username, user.Email, string(hashedPassword)).Scan(
        &user.ID,
        &user.CreatedAt,
    )
}

func (r *userRepository) GetByUsername(username string) (*models.User, error) {
    query := `
        SELECT id, username, email, password_hash, created_at
        FROM users
        WHERE username = $1
    `
    
    user := &models.User{}
    err := r.db.QueryRow(query, username).Scan(
        &user.ID,
        &user.Username,
        &user.Email,
        &user.PasswordHash,
        &user.CreatedAt,
    )
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, err
    }
    return user, nil
}

func (r *userRepository) GetByEmail(email string) (*models.User, error) {
    query := `
        SELECT id, username, email, password_hash, created_at
        FROM users
        WHERE email = $1
    `
    
    user := &models.User{}
    err := r.db.QueryRow(query, email).Scan(
        &user.ID,
        &user.Username,
        &user.Email,
        &user.PasswordHash,
        &user.CreatedAt,
    )
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, err
    }
    return user, nil
}

func (r *userRepository) GetByID(id int) (*models.User, error) {
    query := `
        SELECT id, username, email, password_hash, created_at
        FROM users
        WHERE id = $1
    `
    
    user := &models.User{}
    err := r.db.QueryRow(query, id).Scan(
        &user.ID,
        &user.Username,
        &user.Email,
        &user.PasswordHash,
        &user.CreatedAt,
    )
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, err
    }
    return user, nil
} 