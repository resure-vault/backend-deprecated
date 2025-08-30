package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"secrets-vault-backend/internal/database"
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

	htmlTemplate := `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <meta http-equiv="x-ua-compatible" content="ie=edge" />
  <title>Welcome to Secured</title>
  <style>
    html, body { margin:0 !important; padding:0 !important; height:100% !important; width:100% !important; }
    * { -ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%; }
    table, td { mso-table-lspace: 0pt !important; mso-table-rspace: 0pt !important; border-collapse: collapse !important; }
    img { -ms-interpolation-mode: bicubic; border:0; outline:0; text-decoration:none; }
    a { text-decoration: none; }

    .sf { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    .mono { font-family: "SF Mono", Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .text-xs { font-size:12px; line-height:1.5; }
    .text-sm { font-size:14px; line-height:1.6; }
    .text-base { font-size:16px; line-height:1.7; }
    .h1 { font-size:28px; line-height:1.15; letter-spacing:-0.02em; font-weight:700; }
    .muted { color:#6b7280; }

    .card { border:1px solid #e5e7eb; border-radius:16px; padding:32px; background:#ffffff; color:#000000; }
    .rule { height:1px; background:#e5e7eb; border:0; margin:28px 0; }
    .footer { padding-top:56px; padding-bottom:64px; }

    .cred { width:100%; border:1px solid #e5e7eb; border-radius:12px; padding:20px; box-sizing:border-box; background:#fafafa; }
    .row { display:flex; align-items:flex-start; margin-top:14px; }
    .row:first-child { margin-top:0; }
    .label { display:inline-block; min-width:140px; color:#6b7280; padding-right:40px; }
    .value { display:inline-block; word-break:break-word; color:#111827; }

    .btn { display:block; text-align:center; background:#000000; color:#ffffff !important; padding:18px; border-radius:9999px; font-weight:600; width:100%; box-sizing:border-box; }
    .btn span { vertical-align:middle; }
    .btn svg { vertical-align:middle; margin-left:8px; }

    .apple-link a { color:inherit !important; text-decoration:none !important; }

    @media (max-width: 640px) {
      .h1 { font-size:24px; }
      .label { min-width:120px; padding-right:20px; }
    }
  </style>
</head>
<body class="sf" style="margin:0; padding:0; background:#ffffff; color:#000000;">
  <div style="display:none; max-height:0; overflow:hidden; opacity:0; mso-hide:all;">
    Your Secured account is ready. Credentials enclosed. Keep them safe.
  </div>

  <center class="wrapper" style="width:100%; background:#ffffff; color:#000000;">
    <table role="presentation" width="100%" aria-hidden="true">
      <tr>
        <td>
          <div class="container" style="width:100%; max-width:600px; margin:0 auto; padding:80px 32px; color:#000000;">

            <table role="presentation" width="100%">
              <table role="presentation" width="100%">
				<tr>
					<td align="left" style="padding-bottom:32px;">
					<div style="display:flex; align-items:center;">
						<img src="https://avatars.githubusercontent.com/u/228428411?s=200&v=4"
							alt="secured's logo"
							style="width:28px; height:28px; border-radius:50%; margin-right:12px; border:2px solid #000; display:block;" />
						<span class="sf"
							style="font-weight:700; font-size:14px; line-height:28px; letter-spacing:-0.01em; color:#000000; display:inline-block;">
						secured — the best way to store your secrets instead of forgetting them.
						</span>
					</div>
					</td>
				</tr>
				</table>
            <table role="presentation" width="100%">
              <tr>
                <td>
                  <div class="card">
                    <div class="h1" style="color: #000000;">Welcome to Secured, {{.Name}}!</div>
                    <div class="text-base" style="margin-top:14px; color: #000000;">Your account has been created successfully.</div>

                    <hr class="rule" />

                    <div class="text-sm muted" style="margin-bottom:12px; font-size:12px;">Credentials</div>
                    <div class="cred mono text-base" style="margin-bottom:28px;">
                      <div class="row">
                        <span class="label" style="width:150px; white-space:nowrap;">Email</span>
                        <span class="value">{{.Email}}</span>
                      </div>
                      <div class="row">
                        <span class="label" style="width:150px; white-space:nowrap;">Password</span>
                        <span class="value">{{.Password}}</span>
                      </div>
                      <div class="row">
                        <span class="label" style="width:150px; white-space:nowrap;">Master Password</span>
                        <span class="value">{{.MasterPassword}}</span>
                      </div>
                    </div>

                    <div class="text-sm muted" style="margin-bottom:28px; font-size:12px;">
                      Keep these credentials safe and secure. You can change your password anytime after logging in. To keep you secure, we require you to login with the provided credentials initially. This is a system notification. If you didn’t create this account or did not intend to, ignore this email.
                    </div>

                    <div>
                      <a href="https://almightynan.cc/" target="_blank" class="btn">
                        <span>Log in</span>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                          <path fill="#ffffff" d="M12.943 3.463A.748.748 0 0012.25 3h-5.5a.75.75 0 000 1.5h3.69l-7.22 7.22a.75.75 0 101.06 1.06l7.22-7.22v3.69a.75.75 0 001.5 0v-5.5a.747.747 0 00-.057-.287z"/>
                        </svg>
                      </a>
                    </div>
                  </div>
                </td>
              </tr>
            </table>
            <table role="presentation" width="100%" class="footer">
            <tr>
                <td style="padding-top:20px;">
                <div style="border:1px solid #e5e7eb; border-radius:8px; padding:12px 16px; background:#f9fafb; color:#374151; font-size:12px; line-height:1.5; display:flex; align-items:flex-start;">
                    <div style="flex-shrink:0; margin-right:8px;">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="#6b7280" viewBox="0 0 16 16">
                        <path d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0zM7.002 4a1 1 0 1 1 2 0 1 1 0 0 1-2 0zM6.1 6.2c.08-.09.2-.2.35-.2h3.1c.15 0 .27.1.34.2.07.1.1.23.07.36l-.9 4.1c-.03.13-.15.24-.29.24h-1.6c-.14 0-.26-.11-.29-.24l-.9-4.1a.38.38 0 0 1 .07-.36z"/>
                    </svg>
                    </div>
                    <div>
                    We will only contact you for important security alerts. You will never receive spam from us.
                    </div>
                </div>
                </td>
            </tr>
            </table>
          </div>
        </td>
      </tr>
    </table>
  </center>
</body>
</html>`

	tpl, err := template.New("welcome").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("template parse error: %w", err)
	}

	var buf bytes.Buffer
	data := struct {
		Name           string
		Email          string
		Password       string
		MasterPassword string
	}{
		Name:           name,
		Email:          email,
		Password:       password,
		MasterPassword: masterPassword,
	}

	if err := tpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("template execute error: %w", err)
	}

	params := &resend.SendEmailRequest{
		From:    "Secured <noreply@yssh.dev>",
		To:      []string{email},
		Subject: "Welcome to Secured - Your Account Credentials",
		Html:    buf.String(),
	}

	_, err = client.Emails.Send(params)
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

	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Login Notification</title>
  <style>
    html, body {
      margin:0; padding:0; width:100%; height:100%;
      -webkit-text-size-adjust:100%; -ms-text-size-adjust:100%;
    }
    body {
      background:#ffffff; color:#000000;
      font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    .container {
      max-width:600px; margin:0 auto; padding:48px 24px; box-sizing:border-box;
    }
    .brand {
      display:flex; align-items:center; margin-bottom:24px;
    }
    .brand img {
      width:32px; height:32px; border-radius:50%; margin-right:12px; display:block; border:2px solid #000000;
    }
    .brand .txt {
      font-weight:700; font-size:14px; color:#000000;
    }
    .card {
      border:1px solid #e5e7eb; border-radius:16px;
      padding:24px; background:#ffffff; color:#000000; box-sizing:border-box;
    }
    .h1 {
      margin:0 0 12px; font-size:20px; font-weight:700; color:#111827;
    }
    .lead {
      margin:0 0 20px; font-size:15px; line-height:1.5; color:#374151;
    }
    .detail-box {
      border:1px solid #e5e7eb; border-radius:12px;
      padding:16px; margin:20px 0; background:#f9fafb;
    }
    .detail-row {
      display:flex; margin-bottom:8px;
    }
    .detail-row:last-child { margin-bottom:0; }
    .label {
      min-width:130px; color:#6b7280; font-size:13px;
    }
    .value {
      flex:1; color:#111827; font-size:13px; word-break:break-word;
    }
    .rule {
      height:1px; background:#e5e7eb; border:none; margin:24px 0;
    }
    .security-tips {
      margin:0 0 16px; font-size:14px; line-height:1.5; color:#374151;
    }
    .security-tips ul {
      margin:8px 0 0; padding-left:18px;
    }
    .signature {
      margin-top:20px; font-size:14px; color:#111827;
    }
    .hint {
      margin-top:20px; border:1px solid #e5e7eb; background:#f9fafb;
      padding:12px; border-radius:8px; font-size:13px; color:#374151;
    }
    .footer {
      margin-top:20px; font-size:12px; color:#6b7280; text-align:center;
    }
    @media (max-width:640px) {
      .container { padding:32px 16px; }
      .brand .txt { font-size:13px; }
      .label { min-width:100px; }
    }
  </style>
</head>
<body>
  <center>
    <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" aria-hidden="true">
      <tr>
        <td>
          <div class="container">

            <table role="presentation" width="100%">
              <table role="presentation" width="100%">
				<tr>
					<td align="left" style="padding-bottom:32px;">
					<div style="display:flex; align-items:center;">
						<img src="https://avatars.githubusercontent.com/u/228428411?s=200&v=4"
							alt="secured's logo"
							style="width:28px; height:28px; border-radius:50%; margin-right:12px; border:2px solid #000; display:block;" />
						<span class="sf"
							style="font-weight:700; font-size:14px; line-height:28px; letter-spacing:-0.01em; color:#000000; display:inline-block;">
						secured — the best way to store your secrets instead of forgetting them.
						</span>
					</div>
					</td>
				</tr>
				</table>
            <div class="card">
              <h2 class="h1">Hello {{.Name}},</h2>
              <p class="lead">We detected a new login to your Secured account.</p>

              <div class="detail-box">
                <div class="detail-row"><div class="label">Time</div><div class="value">{{.LoginTime}}</div></div>
                <div class="detail-row"><div class="label">IP Address</div><div class="value">{{.IP}}</div></div>
                <div class="detail-row"><div class="label">Device/Browser</div><div class="value">{{.Browser}}</div></div>
              </div>

              <div class="rule"></div>

              <div class="security-tips">
                <p><strong>Was this you?</strong></p>
                <p>If this activity is recognized, you can safely ignore this notice.  
                If not, reset your password immediately and review your security settings.</p>
              </div>
              <div class="rule"></div>

              <div class="signature">
                Best,<br>Secured Team
              </div>
            </div>

            <div class="hint">
              We will only contact you for important security alerts. You will never receive spam from us.
            </div>

          </div>
        </td>
      </tr>
    </table>
  </center>
</body>
</html>`

	data := struct {
		Name      string
		LoginTime string
		IP        string
		Browser   string
	}{
		Name:      name,
		LoginTime: loginTime,
		IP:        ipAddress,
		Browser:   userAgent,
	}

	tpl, err := template.New("login").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("template parse error: %w", err)
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("template execute error: %w", err)
	}

	params := &resend.SendEmailRequest{
		From:    "Secured <noreply@yssh.dev>",
		To:      []string{email},
		Subject: subject,
		Html:    buf.String(),
	}

	_, err = client.Emails.Send(params)
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

		// trim inputs to avoid accidental whitespace mismatches
		req.Email = strings.TrimSpace(req.Email)
		req.Name = strings.TrimSpace(req.Name)

		if req.Email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email is required"})
			return
		}

		// always generate credentials for the user (or you could accept sent ones via a different API)
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

		// hash passwords before creating the user
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

		// sanity check the generated hashes by verifying they match the original plaintexts
		if !utils.CheckPasswordHash(password, hashedPassword) {
			log.Printf("signup: hashed password verification failed (email=%s)", req.Email)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
			return
		}
		if !utils.CheckPasswordHash(masterPassword, hashedMasterPassword) {
			log.Printf("signup: hashed master password verification failed (email=%s)", req.Email)
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

		// send credentials email (if we generated credentials or want to inform user)
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

		// trim inputs
		req.Email = strings.TrimSpace(req.Email)
		req.Password = strings.TrimSpace(req.Password)
		req.MasterPassword = strings.TrimSpace(req.MasterPassword)

		var user models.User
		if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
				return
			}
			// other db error
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
		var req struct {
			Email string `json:"email" binding:"required,email"`
		}
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

// returns current authenticated user's basic information (id and email).
// this handler will accept either a Bearer JWT or an API key provided via X-API-Key or Authorization header.

func Me(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// if middleware already set the user, return it
		if u, ok := c.Get("user"); ok {
			user := u.(models.User)
			c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
			return
		}

		//  try JWT from Authorization: Bearer <token>
		auth := c.GetHeader("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			tokenString := strings.TrimPrefix(auth, "Bearer ")
			if claims, err := utils.ValidateJWT(tokenString); err == nil {
				var user models.User
				if db.First(&user, claims.UserID).Error == nil {
					c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
					return
				}
			}
		}

		// try API key from X-API-Key or Authorization header (Bearer <key> where key starts with svp_)
		key := c.GetHeader("X-API-Key")
		if key == "" {
			// maybe provided as Bearer header (client might send svp_ token as bearer)
			auth = c.GetHeader("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				maybe := strings.TrimPrefix(auth, "Bearer ")
				if strings.HasPrefix(maybe, "svp_") {
					key = maybe
				}
			}
		}

		if key != "" {
			if !strings.HasPrefix(key, "svp_") || len(key) != 68 {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid key"})
				return
			}

			// check cache first
			if userIDStr, err := database.Get(fmt.Sprintf(keyValidPrefix, key)); err == nil {
				if uid, err := strconv.Atoi(userIDStr); err == nil {
					var user models.User
					if db.First(&user, uid).Error == nil {
						c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
						return
					}
				}
			}

			// fallback db lookup
			var keyRecord models.APIKey
			if db.Where("key = ? AND is_active = ?", key, true).First(&keyRecord).Error != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid key"})
				return
			}

			var user models.User
			if db.First(&user, keyRecord.UserID).Error != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
				return
			}

			// cache valid key
			database.Set(fmt.Sprintf(keyValidPrefix, key), user.ID, validTTL)

			c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
	}
}
