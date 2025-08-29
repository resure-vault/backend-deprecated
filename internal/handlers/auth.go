package handlers

import (
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"
    "time"

    "secrets-vault-backend/internal/models"
    "secrets-vault-backend/internal/utils"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgconn"
    "github.com/resend/resend-go/v2"
    "gorm.io/gorm"
)

func generateRandomPassword(length int) (string, error) {
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

func sendPasswordEmail(email, name, password, masterPassword string) error {
    apiKey := os.Getenv("RESEND_API_KEY")
    if apiKey == "" {
        return errors.New("RESEND_API_KEY not set")
    }

    client := resend.NewClient(apiKey)

    subject := "Welcome to Secured - Your Account Credentials"
    htmlContent := fmt.Sprintf(`
    <h2>Welcome to Secured, %s!</h2>
    <p>Your account has been created successfully. Here are your credentials:</p>
    <p><strong>Email:</strong> %s</p>
    <p><strong>Password:</strong> %s</p>
    <p><strong>Master Password:</strong> %s</p>
    <p><em>Please keep these credentials safe and secure.</em></p>
    <p>You can now login to your account at Secured.</p>
    `, name, email, password, masterPassword)

    params := &resend.SendEmailRequest{
        From:    "Secured <noreply@yssh.dev>",
        To:      []string{email},
        Subject: subject,
        Html:    htmlContent,
    }

    _, err := client.Emails.Send(params)
    return err
}

func sendLoginNotificationEmail(email, name, ipAddress, userAgent string) error {
    apiKey := os.Getenv("RESEND_API_KEY")
    if apiKey == "" {
        return errors.New("RESEND_API_KEY not set")
    }

    client := resend.NewClient(apiKey)

    loginTime := time.Now().Format("January 2, 2006 at 3:04 PM MST")
    
    subject := "New Login to Your Secured Account"
    htmlContent := fmt.Sprintf(`
    <h2>Hello %s,</h2>
    <p>We detected a new login to your Secured account.</p>
    
    <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <h3>Login Details:</h3>
        <p><strong>Time:</strong> %s</p>
        <p><strong>IP Address:</strong> %s</p>
        <p><strong>Device/Browser:</strong> %s</p>
    </div>

    <p><strong>Was this you?</strong></p>
    <p>If this was you, no action is needed.</p>
    <p>If this wasn't you, please secure your account immediately by resetting your password.</p>
    
    <p>For security reasons, we recommend:</p>
    <ul>
        <li>Using strong, unique passwords</li>
        <li>Enabling two-factor authentication when available</li>
        <li>Regularly monitoring your account activity</li>
    </ul>
    
    <p>If you have any concerns about your account security, please contact our support team.</p>
    
    <p>Stay secure,<br>
    Secured Team</p>
    
    <hr style="margin-top: 30px;">
    <p style="font-size: 12px; color: #666;">
        This is an automated security notification. Please do not reply to this email.
    </p>
    `, name, loginTime, ipAddress, userAgent)

    params := &resend.SendEmailRequest{
        From:    "Secured Security <security@yssh.dev>",
        To:      []string{email},
        Subject: subject,
        Html:    htmlContent,
    }

    _, err := client.Emails.Send(params)
    return err
}

func addToResendAudience(email, name string) error {
    apiKey := os.Getenv("RESEND_API_KEY")
    audienceId := os.Getenv("RESEND_AUDIENCE_ID")
    
    if apiKey == "" || audienceId == "" {
        return errors.New("RESEND_API_KEY or RESEND_AUDIENCE_ID not set")
    }

    client := resend.NewClient(apiKey)

    params := &resend.CreateContactRequest{
        Email:      email,
        FirstName:  name,
        AudienceId: audienceId,
    }

    _, err := client.Contacts.Create(params)
    return err
}

func getClientIP(c *gin.Context) string {
    clientIP := c.ClientIP()
    if clientIP == "" {
        clientIP = "Unknown"
    }
    return clientIP
}

func getUserAgent(c *gin.Context) string {
    userAgent := c.GetHeader("User-Agent")
    if userAgent == "" {
        userAgent = "Unknown Browser/Device"
    }
    return userAgent
}

func Signup(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        var req models.SignupRequest
        if err := c.ShouldBindJSON(&req); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        password, err := generateRandomPassword(12)
        if err != nil {
            log.Printf("error generating password: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
            return
        }

        masterPassword, err := generateRandomPassword(16)
        if err != nil {
            log.Printf("error generating master password: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
            return
        }

        hashedPassword, err := utils.HashPassword(password)
        if err != nil {
            log.Printf("error hashing password: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
            return
        }

        hashedMasterPassword, err := utils.HashPassword(masterPassword)
        if err != nil {
            log.Printf("error hashing master password: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
            return
        }

        user := models.User{
            Name:               req.Name,
            Email:              req.Email,
            Password:           hashedPassword,
            MasterPasswordHash: hashedMasterPassword,
        }

        tx := db.Begin()
        if tx.Error != nil {
            log.Printf("failed to begin transaction: %v", tx.Error)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
            return
        }

        if err := tx.Create(&user).Error; err != nil {
            tx.Rollback()
            var pgErr *pgconn.PgError
            if errors.As(err, &pgErr) {
                if pgErr.Code == "23505" {
                    c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
                    return
                }
            }

            msg := strings.ToLower(err.Error())
            if strings.Contains(msg, "duplicate") || strings.Contains(msg, "unique") {
                c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
                return
            }

            log.Printf("failed to create user: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
            return
        }

        if err := tx.Commit().Error; err != nil {
            log.Printf("failed to commit transaction: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
            return
        }

        if err := sendPasswordEmail(user.Email, user.Name, password, masterPassword); err != nil {
            log.Printf("failed to send password email: %v", err)
        }

        if err := addToResendAudience(user.Email, user.Name); err != nil {
            log.Printf("failed to add to resend audience: %v", err)
        }

        token, err := utils.GenerateJWT(user.ID)
        if err != nil {
            log.Printf("failed to generate token: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
            return
        }

        c.JSON(http.StatusCreated, models.LoginResponse{
            User:  user,
            Token: token,
        })
    }
}

func Login(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        var req models.LoginRequest
        if err := c.ShouldBindJSON(&req); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        var user models.User
        if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
            if errors.Is(err, gorm.ErrRecordNotFound) {
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
                return
            }
            log.Printf("db error during login lookup: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
            return
        }

        if user.Password == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Account not activated. Please check your email."})
            return
        }

        if !utils.CheckPasswordHash(req.Password, user.Password) {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
            return
        }

        if !utils.CheckPasswordHash(req.MasterPassword, user.MasterPasswordHash) {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid master password"})
            return
        }

        token, err := utils.GenerateJWT(user.ID)
        if err != nil {
            log.Printf("failed to generate token: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
            return
        }

        clientIP := getClientIP(c)
        userAgent := getUserAgent(c)
        
        if err := sendLoginNotificationEmail(user.Email, user.Name, clientIP, userAgent); err != nil {
            log.Printf("failed to send login notification email: %v", err)
        }

        c.JSON(http.StatusOK, models.LoginResponse{
            User:  user,
            Token: token,
        })
    }
}

func ForgotPassword(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        var req models.ForgotPasswordRequest
        if err := c.ShouldBindJSON(&req); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        var user models.User
        if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
            if errors.Is(err, gorm.ErrRecordNotFound) {
                c.JSON(http.StatusNotFound, gin.H{"error": "Email not registered"})
                return
            }
            log.Printf("db error during forgot password lookup: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
            return
        }

        if user.Password == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Email not registered"})
            return
        }

        password, err := generateRandomPassword(12)
        if err != nil {
            log.Printf("error generating password: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
            return
        }

        masterPassword, err := generateRandomPassword(16)
        if err != nil {
            log.Printf("error generating master password: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
            return
        }

        hashedPassword, err := utils.HashPassword(password)
        if err != nil {
            log.Printf("error hashing password: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
            return
        }

        hashedMasterPassword, err := utils.HashPassword(masterPassword)
        if err != nil {
            log.Printf("error hashing master password: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
            return
        }

        if err := db.Model(&user).Updates(models.User{
            Password:           hashedPassword,
            MasterPasswordHash: hashedMasterPassword,
        }).Error; err != nil {
            log.Printf("failed to update user password: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
            return
        }

        if err := sendPasswordEmail(user.Email, user.Name, password, masterPassword); err != nil {
            log.Printf("failed to send password email: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send password email"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"message": "New password sent to your email"})
    }
}
