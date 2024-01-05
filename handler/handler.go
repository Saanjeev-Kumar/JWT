package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

type Credential struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

type Claim struct {
	Username string
	jwt.RegisteredClaims
}

var jwtKey = []byte("my_secret_key")

func generateJWTtoken(w http.ResponseWriter, username string, expirationTime time.Time) (string, error) {

	claim := &Claim{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	// Declare the token with Algo used for sigining,and claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	// create the JWT string
	tokenString, err := token.SignedString(jwtKey)

	// Finally we set client cookie for "token" as the JWT we just generated
	// we also set an expirey time ehich is same as the token itself
	fmt.Println("JWT TOKEN:", tokenString)
	return tokenString, err

}

func Signin(w http.ResponseWriter, r *http.Request) {
	var creds Credential
	expirationTime := time.Now().Add(time.Minute * 5)
	err := json.NewDecoder(r.Body).Decode(&creds)

	if err != nil {
		fmt.Println("eroor---->1")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, ok := users[creds.UserName]

	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := generateJWTtoken(w, creds.UserName, expirationTime)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   token,
		Expires: expirationTime,
	})
	fmt.Printf("%s Logged in successfully \n", creds.UserName)
	w.Write([]byte(fmt.Sprintf("%s Logged in successfully", creds.UserName)))
	//eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6InVzZXIxIiwiZXhwIjoxNzA0NDUyMDUzfQ.UGv8rrucjgJg9WsQVDGe9a92CUot0kMIDOSoOPRZLvk
}

func Welcome(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}

	tknStr := cookie.Value

	// initialize a new instance of claim

	claim := &Claim{}
	fmt.Println("Before Parse WELOCME", jwtKey)

	tkn, err := jwt.ParseWithClaims(tknStr, claim, func(t *jwt.Token) (interface{}, error) {
		fmt.Println(jwtKey)
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	fmt.Printf("Welcome %s ! \n", claim.Username)
	w.Write([]byte(fmt.Sprintf("Welcome %s !", claim.Username)))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Refresh")

	cookie, err := r.Cookie("token")
	fmt.Println("cookie struct--->", cookie)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tknStr := cookie.Value
	fmt.Println("token---------->", tknStr)
	claim := &Claim{}
	fmt.Println("Before Parse", jwtKey)

	tkn, err := jwt.ParseWithClaims(tknStr, claim, func(t *jwt.Token) (interface{}, error) {
		fmt.Println(jwtKey)
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}
	fmt.Println("----------------------2-----------------")
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	fmt.Println("----------------------3-----------------")
	// untill this point code was same
	// In this case a new token will only be issued only enough time is elapsed
	// In this case new token will only be issued if the ild token is within
	// 30 second of expiration.Otherwise,return a bad request status

	if time.Until(claim.ExpiresAt.Time) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	fmt.Println("----------------------4-----------------")
	expirationTime := time.Now().Add(time.Minute * 5)
	claim.ExpiresAt = jwt.NewNumericDate(expirationTime)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	tokenStr, err := token.SignedString(jwtKey)
	fmt.Println("----------------------5-----------------")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Println("----------------------6-----------------")
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenStr,
		Expires: expirationTime,
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	// Immediatly clear the token cookie

	_, err := r.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})
	w.Write([]byte(fmt.Sprint("Logout succefully")))
}
