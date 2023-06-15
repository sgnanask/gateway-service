package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func Authorization(claimName string, claimValue string) gin.HandlerFunc {
	return func(c *gin.Context) {
		getClaims, permissionOk := c.Get("claims")
		if permissionOk {
			claims := getClaims.([]interface{})
			permissionOk = validateClaims(claims, claimName, claimValue)
		}

		if !permissionOk {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"status": http.StatusUnauthorized,
				"error":  []string{"you do not have permission"},
			})
			return
		}

		c.Next()
	}
}

func validateClaims(userClaims []interface{}, claimType string, claimValue string) bool {
	_claimType := strings.TrimSpace(claimType)
	_claimValue := strings.TrimSpace(claimValue)
	if len(_claimType) == 0 || len(_claimValue) == 0 {
		return false
	}

	_claimValueSplitted := strings.Split(_claimValue, ",")

	for _, interator := range userClaims {
		result := interator.(map[string]interface{})
		if result["type"] == _claimType {
			userValueClaimSplitted := strings.Split(result["value"].(string), ",")

			return arrayContainsArray(_claimValueSplitted, userValueClaimSplitted)
		}
	}

	return false
}

func arrayContainsArray(array1 []string, array2 []string) bool {
	for _, val1 := range array1 {
		found := false
		for _, val2 := range array2 {
			if val1 == val2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
