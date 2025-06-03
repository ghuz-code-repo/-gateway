package models

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
	"strconv"
	"strings"
)

// EmailConfig holds SMTP configuration
type EmailConfig struct {
	Host       string
	Port       string
	Username   string
	Password   string
	From       string
	UseTLS     bool
	UseAuth    bool
	AuthMethod string
	Debug      bool
}

// GetEmailConfig loads email configuration from environment variables
func GetEmailConfig() EmailConfig {
	useTLS, _ := strconv.ParseBool(os.Getenv("SMTP_USE_TLS"))
	useAuth, _ := strconv.ParseBool(os.Getenv("SMTP_USE_AUTH"))
	debug, _ := strconv.ParseBool(os.Getenv("SMTP_DEBUG"))

	return EmailConfig{
		Host:       os.Getenv("SMTP_HOST"),
		Port:       os.Getenv("SMTP_PORT"),
		Username:   os.Getenv("SMTP_USERNAME"),
		Password:   os.Getenv("SMTP_PASSWORD"),
		From:       os.Getenv("SMTP_FROM"),
		UseTLS:     useTLS,
		UseAuth:    useAuth,
		AuthMethod: os.Getenv("SMTP_AUTH_METHOD"),
		Debug:      debug,
	}
}

// SendEmailNotification sends an email notification
func SendEmailNotification(to, subject, body string) error {

	config := GetEmailConfig()

	// Use default values if environment variables are not set
	if config.Host == "" {
		config.Host = "smtp.gmail.com" // Default SMTP host
	}
	if config.Port == "" {
		config.Port = "587" // Default SMTP port
	}
	if config.From == "" {
		config.From = config.Username // Default sender
	}
	if config.AuthMethod == "" {
		config.AuthMethod = "plain" // Default to PLAIN auth
	}

	// Debug output
	if config.Debug {
		fmt.Printf("Email config: Host=%s, Port=%s, Username=%s, UseTLS=%v, UseAuth=%v, AuthMethod=%s\n",
			config.Host, config.Port, config.Username, config.UseTLS, config.UseAuth, config.AuthMethod)
	}

	// Check if required credentials are present
	if config.UseAuth && (config.Username == "" || config.Password == "") {
		fmt.Println("SMTP credentials required but not configured, email notification skipped")
		return nil
	}

	// Compose the message
	message := []string{
		"From: " + config.From,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}

	messageBody := strings.Join(message, "\r\n")

	// Server address
	addr := fmt.Sprintf("%s:%s", config.Host, config.Port)

	// Create SMTP client
	var client *smtp.Client
	var err error

	if config.UseTLS {
		// Create TLS config
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         config.Host,
		}

		// Connect to the server with TLS
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("TLS dial error: %v", err)
		}

		client, err = smtp.NewClient(conn, config.Host)
		if err != nil {
			return fmt.Errorf("SMTP client error: %v", err)
		}
	} else {
		// Connect to the server without TLS
		client, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("SMTP dial error: %v", err)
		}

		// Start TLS if available
		if ok, _ := client.Extension("STARTTLS"); ok {
			config := &tls.Config{ServerName: config.Host}
			if err = client.StartTLS(config); err != nil {
				return fmt.Errorf("start TLS error: %v", err)
			}
		}
	}
	defer client.Quit()

	// Authenticate if needed
	if config.UseAuth {
		var auth smtp.Auth

		switch strings.ToLower(config.AuthMethod) {
		case "plain":
			auth = smtp.PlainAuth("", config.Username, config.Password, config.Host)
		case "login":
			auth = LoginAuth(config.Username, config.Password)
		case "crammd5":
			auth = smtp.CRAMMD5Auth(config.Username, config.Password)
		default:
			// Default to plain auth
			auth = smtp.PlainAuth("", config.Username, config.Password, config.Host)
		}

		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication error: %v", err)
		}
	}

	// Set the sender and recipient
	if err = client.Mail(config.From); err != nil {
		return fmt.Errorf("SMTP MAIL command error: %v", err)
	}

	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT command error: %v", err)
	}

	// Send the email body
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA command error: %v", err)
	}

	_, err = fmt.Fprint(wc, messageBody)
	if err != nil {
		return fmt.Errorf("SMTP body write error: %v", err)
	}

	err = wc.Close()
	if err != nil {
		return fmt.Errorf("SMTP data close error: %v", err)
	}

	fmt.Printf("Email notification sent to %s\n", to)
	return nil
}

// LoginAuth is a custom implementation of the LOGIN authentication mechanism
type loginAuth struct {
	username, password string
}

// LoginAuth returns an Auth that implements the LOGIN authentication mechanism
func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

// Start begins an authentication with the server
func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

// Next continues the authentication
func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, fmt.Errorf("unknown LOGIN challenge: %s", fromServer)
		}
	}
	return nil, nil
}
