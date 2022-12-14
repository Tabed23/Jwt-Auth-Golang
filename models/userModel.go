package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `json:"_id" bson:"_id"`
	FirstName    *string            `json:"first_name" validate:"required,min=4,max=15"`
	LastName     *string            `json:"last_name" validate:"required,min=4,max=15"`
	Password     *string            `json:"password" validate:"required,min=6"`
	Email        *string            `json:"email" validate:"email,required"`
	Phone        *string            `json:"phone" validate:"required"`
	Token        *string            `json:"token"`
	UserType     *string            `json:"user_type" validate:"required,eq=ADMIN|eq=USER"`
	RefreshToken *string            `json:"refresh_token"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated"`
	UserID       string             `json:"user_id"`
}

type UserLogin struct {
	Password     *string            `json:"password" validate:"required,min=6"`
	Email        *string            `json:"email" validate:"email,required"`
}
