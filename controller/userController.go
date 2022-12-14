package controller

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Tabed23/jwt-auth/databases"
	"github.com/Tabed23/jwt-auth/helper"
	"github.com/Tabed23/jwt-auth/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollections *mongo.Collection = databases.OpenCollection(databases.Client, "users")
var validate = validator.New()

func HashPassword(password string) string {
	bytesPassword, err := bcrypt.GenerateFromPassword([]byte(password), 14)

	if err != nil {
		log.Panic(err)
	}

	return string(bytesPassword)
}

func VerifyPassword(userpassword string, foundpassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(userpassword), []byte(foundpassword))
	isValid := true
	msg := ""

	if err != nil {
		msg = "email of password is incorrect"
		isValid = false

	}

	return isValid, msg
}

func SignUp(c *gin.Context) {

	var user models.User

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)

	validateErr := validate.Struct(user)

	if validateErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": validateErr.Error()})
	}

	count, err := userCollections.CountDocuments(ctx, bson.M{"email": user.Email})

	defer cancel()
	if err != nil {
		log.Panic(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error accured  while checking user email address"})
	}
	if count > 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "this email address is already exists"})
		return
	}

	password := HashPassword(*user.Password)

	user.Password = &password

	count, err = userCollections.CountDocuments(ctx, bson.M{"phone": user.Phone})

	defer cancel()

	if err != nil {
		log.Panic(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error accured  while checking user phone number"})
		return
	}

	if count > 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "this phone number is already exists"})
		return
	}

	user.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	user.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	user.ID = primitive.NewObjectID()

	user.UserID = user.ID.Hex()

	token, refreshToken, _ := helper.GenerateAllToken(*user.Email, *user.FirstName, *user.LastName, *user.UserType, user.UserID)

	user.Token = &token

	user.RefreshToken = &refreshToken

	resultInsert, err := userCollections.InsertOne(ctx, user)

	if err != nil {
		msg := "User item was not created"
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	defer cancel()

	c.JSON(http.StatusOK, resultInsert)
}

func Login(c *gin.Context) {
	var user models.UserLogin

	var foundUser models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)

	err := userCollections.FindOne(ctx, bson.M{"email": *user.Email}).Decode(&foundUser)

	defer cancel()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "email or password is  not correct" + err.Error()})
		return
	}

	passwordValid, msg := VerifyPassword(*user.Password, *foundUser.Password)

	defer cancel()

	if !passwordValid {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
	}

	if foundUser.Email == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		return
	}
	token, refreshtoken, err := helper.GenerateAllToken(*foundUser.Email, *foundUser.FirstName, *foundUser.LastName, *foundUser.UserType, foundUser.UserID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	helper.UpdateAllToken(token, refreshtoken, foundUser.UserID)

	err = userCollections.FindOne(ctx, bson.M{"user_id": foundUser.UserID}).Decode(&foundUser)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": &foundUser,
	})
}

func GetUser(c *gin.Context) {
	userId := c.Param("user_id")
	if err := helper.MatchUserTypeToUid(c, userId); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var user models.User

	err := userCollections.FindOne(ctx, bson.M{"userid": userId}).Decode(&user)

	defer cancel()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

func GetUsers(c *gin.Context) {
	if err := helper.CheckUserType(c, "ADMIN"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	records, err := strconv.Atoi(c.Query("recordPerPage"))
	if err != nil || records < 1 {
		records = 10
	}
	page, err := strconv.Atoi(c.Query("page"))
	if err != nil || page < 1 {
		page = 1
	}
	startIndex := (page - 1) * records
	startIndex, _ = strconv.Atoi(c.Query("startIndex"))

	matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}

	groupStage := bson.D{{Key: "$group", Value: bson.D{
		{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
		{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
		{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
	}}}

	projectsStage := bson.D{
		{
			Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "user_items", Value: bson.D{
					{Key: "$slice", Value: []interface{}{"$data", startIndex, records}},
				}},
			},
		}}
	result, err := userCollections.Aggregate(ctx, mongo.Pipeline{
		matchStage,
		groupStage,
		projectsStage,
	})
	defer cancel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error accured while listing users"})
	}
	var allUser []bson.M
	if err = result.All(ctx, &allUser); err != nil {
		log.Fatal(err)
	}

	c.JSON(http.StatusOK, allUser[0])
}
