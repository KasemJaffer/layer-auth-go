package jws

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

// Define Identity Token Variables
var (
	layerProviderID  = "LAYER-PROVIDER-ID"
	layerKeyID       = "LAYER-KEY-ID"
	PRIVATE_KEY_PATH = "private_key.pem"
)

type ResponseObject struct {
	identityToken string
}

type RequestObject struct {
	userID string
	nonce  string
}

func init() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/authenticate", authenticate)
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, This is JWS Authenticator Server")
}

func authenticate(w http.ResponseWriter, r *http.Request) {

	//Parse the body and check if it is valid
	decoder := json.NewDecoder(r.Body)
	var body RequestObject
	err := decoder.Decode(&body)
	if err != nil {
		http.Error(w,
			ToJsonString(map[string]interface{}{
				"Message": "Invalid body: Must contain userID and nonce.",
				"Error":   err.Error(),
			}), http.StatusBadRequest)
		return
	}

	// Construct the header
	header := map[string]interface{}{
		"typ": "JWS",           // Expresses a MIME Type of application/JWS
		"alg": "RS256",         // Expresses the type of algorithm used to sign the token, must be RS256
		"cty": "layer-eit;v=1", // Express a Content Type of application/layer-eit;v=1
		"kid": layerKeyID,
	}

	currentTimeInSeconds := time.Now().Second()
	expirationTime := currentTimeInSeconds + 10000

	// Construct the claim
	claim := map[string]interface{}{
		"iss": layerProviderID,      // The Layer Provider ID
		"prn": body.userID,          // User Identifiers
		"iat": currentTimeInSeconds, // Time of Token Issuance
		"exp": expirationTime,       // Arbitrary time of Token Expiration
		"nce": body.nonce,           //Nonce obtained from the request
	}

	// get the key
	keyData, err := loadData(PRIVATE_KEY_PATH)
	if err != nil {
		http.Error(w,
			ToJsonString(map[string]interface{}{
				"Message": "Couldn't read key",
				"Error":   err.Error(),
			}), http.StatusInternalServerError)
		return
	}

	// create a new token
	signingMethod := jwt.GetSigningMethod("RS256")
	token := jwt.New(signingMethod)
	token.Claims = claim
	token.Header = header

	if out, err := token.SignedString(keyData); err == nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, ToJsonString(ResponseObject{out}))

	} else {
		http.Error(w,
			ToJsonString(map[string]interface{}{
				"Message": "Error signing token",
				"Error":   err.Error(),
			}), http.StatusInternalServerError)
	}
}

// Helper function to convert objects to JSON
func ToJsonString(data interface{}) (jsonString string) {
	jsonBytes, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		return
	}
	jsonString = string(jsonBytes)
	return jsonString
}

// Helper function to read input from specified file
func loadData(p string) ([]byte, error) {
	if p == "" {
		return nil, fmt.Errorf("No path specified")
	}

	var rdr io.Reader
	if f, err := os.Open(p); err == nil {
		rdr = f
		defer f.Close()
	} else {
		return nil, err
	}
	return ioutil.ReadAll(rdr)
}
