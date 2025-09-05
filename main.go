
package main

import (
    "context"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "log"
    "math/big"
    "net/http"
    "net/smtp"
    "strings"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
    "golang.org/x/crypto/bcrypt"
)

var dbURL = ""
var pool *pgxpool.Pool
var jwtSecret = []byte("supersecretkey")

var smtpFrom = ""  // email 
var smtpPass = "" // password
var smtpHost = "smtp.gmail.com"
var smtpPort = "587"

func initDB() {
    var err error
    pool, err = pgxpool.New(context.Background(), dbURL)
    if err != nil {
        log.Fatal("DB connection error:", err)
    }
    if err := pool.Ping(context.Background()); err != nil {
        log.Fatal("Cannot reach database:", err)
    }
}

type User struct {
    ID           int
    Email        string
    Username     *string
    PasswordHash string
    Verified     bool
}

func generateOTP() string {
    n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
    return fmt.Sprintf("%06d", n.Int64())
}

func sendEmail(to, otp string) {
    subject := "Your Neura OTP Code"
    body := fmt.Sprintf("Hello,\n\nYour OTP code is: %s\n\nIt is valid for 5 minutes.", otp)
    msg := "From: " + smtpFrom + "\n" +
        "To: " + to + "\n" +
        "Subject: " + subject + "\n\n" +
        body

    auth := smtp.PlainAuth("", smtpFrom, smtpPass, smtpHost)
    go func() {
        if err := smtp.SendMail(smtpHost+":"+smtpPort, auth, smtpFrom, []string{to}, []byte(msg)); err != nil {
            fmt.Println("Failed to send OTP email:", err)
        }
    }()
}

type JWTPayload struct {
    UserID int   `json:"user_id"`
    Exp    int64 `json:"exp"`
}

func createJWT(userID int, duration time.Duration) (string, error) {
    header := map[string]string{"alg": "HS256", "typ": "JWT"}
    headerJSON, _ := json.Marshal(header)
    headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

    payload := JWTPayload{
        UserID: userID,
        Exp:    time.Now().Add(duration).Unix(),
    }
    payloadJSON, _ := json.Marshal(payload)
    payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

    unsigned := headerB64 + "." + payloadB64
    h := hmac.New(sha256.New, jwtSecret)
    h.Write([]byte(unsigned))
    signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

    return unsigned + "." + signature, nil
}

func verifyJWT(token string) (JWTPayload, error) {
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        return JWTPayload{}, fmt.Errorf("invalid token")
    }

    unsigned := parts[0] + "." + parts[1]
    h := hmac.New(sha256.New, jwtSecret)
    h.Write([]byte(unsigned))
    expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

    if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
        return JWTPayload{}, fmt.Errorf("invalid signature")
    }

    payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
    var payload JWTPayload
    json.Unmarshal(payloadBytes, &payload)

    if time.Now().Unix() > payload.Exp {
        return JWTPayload{}, fmt.Errorf("token expired")
    }

    return payload, nil
}

func signUpHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
        return
    }

    var req struct {
        Email      string  `json:"email"`
        Username   *string `json:"username"`
        Password   string  `json:"password"`
        Require2FA bool    `json:"require2FA"`
        OTP        string  `json:"otp,omitempty"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    var existingID int
    err := pool.QueryRow(context.Background(), "SELECT id FROM users WHERE email=$1", req.Email).Scan(&existingID)
    if err == nil {
        http.Error(w, "Email already exists", http.StatusConflict)
        return
    }

    hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    var userID int
    err = pool.QueryRow(context.Background(),
        "INSERT INTO users (email, username, password_hash, verified) VALUES ($1,$2,$3,$4) RETURNING id",
        req.Email, req.Username, string(hashed), !req.Require2FA).Scan(&userID)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    if req.Require2FA {
        otp := generateOTP()
        expiry := time.Now().Add(5 * time.Minute)
        _, _ = pool.Exec(context.Background(),
            "INSERT INTO email_otps (user_id, otp_code, expires_at) VALUES ($1,$2,$3)",
            userID, otp, expiry)
        sendEmail(req.Email, otp)
        resp := map[string]interface{}{"status": "otp_required", "message": "OTP sent"}
        json.NewEncoder(w).Encode(resp)
        return
    }

    token, _ := createJWT(userID, 72*time.Hour)
    resp := map[string]interface{}{"status": "ok", "token": token, "expiresAt": time.Now().Add(72 * time.Hour)}
    json.NewEncoder(w).Encode(resp)
}

func signInHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
        return
    }

    var req struct {
        Identifier string `json:"identifier"`
        Password   string `json:"password"`
        IsOTP      bool   `json:"isOTP"`
        OTP        string `json:"otp,omitempty"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    var user User
    err := pool.QueryRow(context.Background(),
        "SELECT id, email, username, password_hash, verified FROM users WHERE email=$1 OR username=$1",
        req.Identifier).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.Verified)
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    if !user.Verified {
        http.Error(w, "User not verified. Please verify OTP.", http.StatusUnauthorized)
        return
    }

    if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    if req.IsOTP && req.OTP == "" {
        otp := generateOTP()
        expiry := time.Now().Add(5 * time.Minute)
        _, _ = pool.Exec(context.Background(),
            "INSERT INTO email_otps (user_id, otp_code, expires_at) VALUES ($1,$2,$3)",
            user.ID, otp, expiry)
        sendEmail(user.Email, otp)
        resp := map[string]interface{}{"status": "otp_required", "message": "OTP sent"}
        json.NewEncoder(w).Encode(resp)
        return
    }

    if req.OTP != "" {
        var expires time.Time
        var used bool
        err := pool.QueryRow(context.Background(),
            "SELECT expires_at, used FROM email_otps WHERE user_id=$1 AND otp_code=$2 ORDER BY id DESC LIMIT 1",
            user.ID, req.OTP).Scan(&expires, &used)
        if err != nil || time.Now().After(expires) || used {
            http.Error(w, "Invalid or expired OTP", http.StatusUnauthorized)
            return
        }
        _, _ = pool.Exec(context.Background(), "UPDATE email_otps SET used=true WHERE otp_code=$1", req.OTP)
        token, _ := createJWT(user.ID, 72*time.Hour)
        resp := map[string]interface{}{"status": "ok", "token": token, "expiresAt": time.Now().Add(72 * time.Hour)}
        json.NewEncoder(w).Encode(resp)
        return
    }

    token, _ := createJWT(user.ID, 72*time.Hour)
    resp := map[string]interface{}{"status": "ok", "token": token, "expiresAt": time.Now().Add(72 * time.Hour)}
    json.NewEncoder(w).Encode(resp)
}

func main() {
    initDB()
    http.HandleFunc("/signup", signUpHandler)
    http.HandleFunc("/signin", signInHandler)
    fmt.Println("✅ Server")
    log.Fatal(http.ListenAndServe("0.0.0.0:3000", nil))
}
