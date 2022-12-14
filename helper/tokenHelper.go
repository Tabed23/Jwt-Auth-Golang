package helper

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Tabed23/jwt-auth/databases"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type SignedDetails struct {
	Email     string
	FirstName string
	LastName  string
	Uid       string
	UserType  string
	jwt.RegisteredClaims
}

var SECRET_KEY string = os.Getenv("SECRET_KEY")

var userCollections *mongo.Collection = databases.OpenCollection(databases.Client, "users")

func GenerateAllToken(email, first_name, last_name, usertype, uid string) (string, string, error) {
	claims := &SignedDetails{
		Email:     email,
		FirstName: first_name,
		LastName:  last_name,
		UserType:  usertype,
		Uid:       uid,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Local().Add(time.Hour * time.Duration(24))),
			Issuer:    email,
		},
	}

	mySigningKey := []byte(SECRET_KEY)
	refreshClaims := &SignedDetails{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Local().Add(time.Hour * time.Duration(24))),
			Issuer:    email,
		},
	}
	Token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	singedToken, err := Token.SignedString(mySigningKey)
	if err != nil {
		fmt.Println("in singedToken generation")
		log.Panic(err)
		return "", "", err
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedrefreshToken, err := refreshToken.SignedString(mySigningKey)
	if err != nil {
		fmt.Println("in signedrefreshToken generation")
		log.Panic(err)
		return "", "", err
	}
	return singedToken, signedrefreshToken, nil
}
func UpdateAllToken(singedtoken string, singedrefreshToken string, userId string) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	var updateObj primitive.D
	updateObj = append(updateObj, bson.E{Key: "token", Value: singedtoken})

	updateObj = append(updateObj, bson.E{Key: "refresh_token", Value: singedrefreshToken})

	updateAt, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	updateObj = append(updateObj, bson.E{Key: "update_at", Value: updateAt})

	upsert := true
	filter := bson.M{"user_id": userId}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	_, err := userCollections.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updateObj},
		},
		&opt,
	)

	defer cancel()
	if err != nil {
		log.Panic(err)
		return
	}
}

func ValidateToken(singedToken string) (claims *SignedDetails, msg string) {
	token, err := jwt.ParseWithClaims(
		singedToken,
		&SignedDetails{},
		func(t *jwt.Token) (interface{}, error) { return []byte(SECRET_KEY), nil },
	)
	if err != nil {
		msg = err.Error()
		return
	}
	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = fmt.Sprintf("the token is not signed, invalid claims" + err.Error())

		return
	}
	if claims.ExpiresAt.Unix() < time.Now().Local().Unix() {
		msg = fmt.Sprintf("token is expired" + err.Error())
		return
	}

	return claims, msg
}
