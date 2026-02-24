package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const baseURL = "https://apiconnect.angelone.in"

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

//////////////////////////////////////////////////////////
// 🔹 MAIN
//////////////////////////////////////////////////////////

func main() {

	// Load .env
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		return
	}

	token := os.Getenv("JWT_TOKEN")

	// If no token → login
	if token == "" {
		fmt.Println("No JWT found. Logging in...")
		token, err = login()
		if err != nil {
			fmt.Println("Login failed:", err)
			return
		}
		fmt.Println("Login success!")
	}

	// Take stock input
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Stock Name (default: SBIN): ")
	stock, _ := reader.ReadString('\n')
	stock = strings.TrimSpace(stock)

	if stock == "" {
		stock = "SBIN"
	}

	err = fetchStock(stock, token)
	if err != nil {
		fmt.Println("Error:", err)
	}
	logout(token)
}

//////////////////////////////////////////////////////////
// 🚪 LOGOUT (MANUAL CALL)
//////////////////////////////////////////////////////////

func logout(token string) error {

	url := baseURL + "/rest/secure/angelbroking/user/v1/logout"

	logoutData := map[string]string{
		"clientcode": os.Getenv("CLIENT_CODE"),
	}

	jsonData, _ := json.Marshal(logoutData)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	setCommonHeaders(req)
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)

	fmt.Println("Logout Response:", string(body))

	// Clear tokens from .env after logout
	updateEnv("JWT_TOKEN", "")
	updateEnv("REFRESH_TOKEN", "")

	return nil
}

// ////////////////////////////////////////////////////////
// 🔐 LOGIN
// ////////////////////////////////////////////////////////
func login() (string, error) {

	url := baseURL + "/rest/auth/angelbroking/user/v1/loginByPassword"

	loginData := map[string]string{
		"clientcode": os.Getenv("CLIENT_CODE"),
		"password":   os.Getenv("PASSWORD"),
		"totp":       generateTOTP(os.Getenv("TOTP_SECRET")),
	}

	jsonData, _ := json.Marshal(loginData)

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	setCommonHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", err
	}

	if result["success"] == false {
		return "", fmt.Errorf("Login failed: %v", result["message"])
	}

	data := result["data"].(map[string]interface{})

	jwt := data["jwtToken"].(string)
	refresh := data["refreshToken"].(string)

	// Save tokens to .env
	updateEnv("JWT_TOKEN", jwt)
	updateEnv("REFRESH_TOKEN", refresh)

	return jwt, nil
}

//////////////////////////////////////////////////////////
// 📈 FETCH STOCK
//////////////////////////////////////////////////////////

func fetchStock(stock string, token string) error {

	url := baseURL + "/rest/secure/angelbroking/market/v1/quote/"

	requestData := map[string]interface{}{
		"mode": "FULL",
		"exchangeTokens": map[string][]string{
			"NSE": {stock},
		},
	}

	jsonData, _ := json.Marshal(requestData)

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	setCommonHeaders(req)
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)

	// Save JSON file
	fileName := stock + ".json"
	err = os.WriteFile(fileName, body, 0644)
	if err != nil {
		return err
	}

	fmt.Println("Saved data to:", fileName)

	return nil
}

//////////////////////////////////////////////////////////
// 🌐 HEADERS
//////////////////////////////////////////////////////////

func setCommonHeaders(req *http.Request) {

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-UserType", "USER")
	req.Header.Set("X-SourceID", "WEB")
	req.Header.Set("X-PrivateKey", os.Getenv("API_KEY"))
	req.Header.Set("X-ClientLocalIP", getLocalIP())
	req.Header.Set("X-ClientPublicIP", getPublicIP())
	req.Header.Set("X-MACAddress", getMacAddress())
}

//////////////////////////////////////////////////////////
// 💾 UPDATE .ENV
//////////////////////////////////////////////////////////

func updateEnv(key, value string) error {

	envMap, err := godotenv.Read(".env")
	if err != nil {
		return err
	}

	envMap[key] = value

	return godotenv.Write(envMap, ".env")
}

//////////////////////////////////////////////////////////
// 🔐 TOTP GENERATOR
//////////////////////////////////////////////////////////

func generateTOTP(secret string) string {

	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)

	counter := time.Now().Unix() / 30

	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], uint64(counter))

	h := hmac.New(sha1.New, key)
	h.Write(counterBytes[:])
	hash := h.Sum(nil)

	offset := hash[len(hash)-1] & 0x0F
	code := binary.BigEndian.Uint32(hash[offset : offset+4])
	code &= 0x7FFFFFFF

	otp := code % 1000000

	return fmt.Sprintf("%06d", otp)
}

//////////////////////////////////////////////////////////
// 🌍 NETWORK HELPERS
//////////////////////////////////////////////////////////

func getLocalIP() string {
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

func getPublicIP() string {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	ip, _ := io.ReadAll(resp.Body)
	return string(ip)
}

func getMacAddress() string {
	interfaces, _ := net.Interfaces()
	for _, i := range interfaces {
		if mac := i.HardwareAddr.String(); mac != "" {
			return mac
		}
	}
	return ""
}
