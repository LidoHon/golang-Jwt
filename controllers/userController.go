package controllers

import (
	"context"
	"log"
	"net/http"
	"strconv"

	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"

	helper "github.com/LidoHon/golang-Jwt/helpers"
	"github.com/LidoHon/golang-Jwt/models"

	"github.com/LidoHon/golang-Jwt/database"
	model "github.com/LidoHon/golang-Jwt/models"
)


var userCollection *mongo.Collection = database.OpenCollection(database.Client, "users")

var validate = validator.New()

func HashPassword(password string)string{
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err !=nil{
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword( userPassword, providedPassword string) ( bool, string){

	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))

	check := true
	msg := ""

	if err !=nil{
		msg = "incorrect credentials"
		check =false
	}
	return check, msg

}

// sign up a user
func SignUp() gin.HandlerFunc{
	return func(c *gin.Context) {

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var user models.User
	if err :=c.BindJSON(&user); err !=nil{
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	validateErr := validate.Struct(user)
	if validateErr != nil{
		c.JSON(http.StatusBadRequest, gin.H{"error": validateErr.Error()})
		return
	}
	// Check if the email already exists
	count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})

	if err != nil{
		log.Panic(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error":"error occurred while checking the email"})
		
	}

	if count > 0{
		c.JSON(http.StatusInternalServerError, gin.H{"error": "this email or phone number already exists"})
	}
// hash the password
	password := HashPassword(*user.Password)
	user.Password = &password

	// Check if the phone number already exists
	count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})



	if err !=nil{
		log.Panic(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while checking for phone number"})
	}

	if count > 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "this email or phone number already exists"})
	}

		// Set creation and update timestamps
	user.Created_at, err = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	if err !=nil{
		log.Panic(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error while formatting created at time"})
	}

	user.Updated_at, err = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	if err !=nil{
		log.Panic(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error while formatting updated at time"})
	}
// Generate user ID and tokens
	user.ID = primitive.NewObjectID()
	user.User_id = user.ID.Hex()
	token,refreshToken, err:= helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, user.User_id)

	if err !=nil{
		log.Panic(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":"error getting the generated token",
		})
	}
	user.Token = &token
	user.Refresh_token = &refreshToken

	// Insert the user into the collection

	resultInsertionNumber, insertError := userCollection.InsertOne(ctx, user)
	if insertError != nil{
		msg := "user item was not created"
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": msg,
		})
		return
	}
	defer cancel()

	c.JSON(http.StatusOK, resultInsertionNumber)

	}
}

// login a user
func Login()  gin.HandlerFunc{
	return func (c *gin.Context){
	ctx, cancel := context.WithTimeout(context.Background(), 100 * time.Second)

	defer cancel()

	var user model.User
	var foundUser model.User

	// Bind JSON input.
	if err := c.BindJSON(&user); err!=nil{
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error()})
		return
	}
// Find user by email
	err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)

	if err !=nil{
		c.JSON(http.StatusUnauthorized, gin.H{"error":"invalid email or password"})
		return
	}

	// Verify password
	passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
	

	if !passwordIsValid {
		c.JSON(http.StatusUnauthorized, gin.H{"error":msg})
		return
	}
	

	// Generate tokens
	token, refreshToken, tokenErr := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name,*foundUser.User_type,  foundUser.User_id, )

	if tokenErr != nil{
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate tokens"})
			return
	}

	// Update tokens in the database
	updateErr := helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)

	if updateErr != nil{
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error updating the tokens"})
		return
	}


// Refresh user data after updating tokens
	err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id }).Decode(&foundUser)

	if err !=nil{
		c.JSON(http.StatusInternalServerError, gin.H{"error":err.Error()})
		return
	}
	// Send response

	c.JSON(http.StatusOK, foundUser)
	}
}



func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context){
		if err := helper.CheckUserType(c, "ADMIN"); err !=nil{
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error()})
				return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))

		if err !=nil || recordPerPage < 1{
			recordPerPage = 10
		}
		page, err1	:= strconv.Atoi(c.Query("page"))
		if err1 !=nil || page<1{
			page = 1
		}
		startIndex := (page -1 ) * recordPerPage
		// startIndex, err = strconv.Atoi(c.Query("startIndex"))

		matchStage := bson.D{{Key: "$match",Value:  bson.D{{}}}}

		groupStage := bson.D{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: "null"},
				{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
				{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
			}},
		}
		projectStage :=bson.D{{
			Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}},
			},
		}}
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
		matchStage, groupStage, projectStage})

		defer cancel()
		if err !=nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while listing user items"})
			return
		}
		var allUsers []bson.M

		if err = result.All(ctx, &allUsers); err !=nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error processing result"})
				return
		}
		if len(allUsers) > 0 {
			c.JSON(http.StatusOK, allUsers[0])
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "no users found"})
		}
	
	}

}


func GetUser() gin.HandlerFunc{
	return func (c *gin.Context){
		userId := c.Param("user_id")

		if err := helper.MatchUserTypeToUid(c, userId); err !=nil{
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error()} )
				return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()
		if err !=nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while fetching user"})
			return
		}
		 c.JSON(http.StatusOK, user)
	}
}