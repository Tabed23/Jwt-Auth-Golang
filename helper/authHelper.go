package helper

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func CheckUserType(c *gin.Context, role string) error {
	userType := c.GetString("user_type")

	if userType != role {
		return errors.New("unauthorized, to access this resource")
	}

	return nil
}

func MatchUserTypeToUid(c *gin.Context, userId string) (err error) {
	userType := c.GetString("user_type")
	uid := c.GetString("uid")
	err = nil
	if userType == "USER" && uid != userId {
		err = errors.New("unauthorized to access user")
		return err
	}

	err = CheckUserType(c, userType)

	return err
}
