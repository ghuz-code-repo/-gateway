package models

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
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

// isIPAddress checks if the given string is an IP address
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// getTLSConfig creates appropriate TLS configuration based on whether host is IP or DNS name
func getTLSConfig(host string) *tls.Config {
	if isIPAddress(host) {
		log.Printf("Host %s is an IP address, using InsecureSkipVerify for TLS", host)
		return &tls.Config{
			InsecureSkipVerify: true,
		}
	} else {
		log.Printf("Host %s is a DNS name, using normal TLS verification", host)
		return &tls.Config{
			ServerName: host,
		}
	}
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
	log.Printf("Attempting to send email to: %s, subject: %s", to, subject)

	config := GetEmailConfig()

	// Use default values if environment variables are not set
	if config.Host == "" {
		config.Host = "smtp.gmail.com" // Default SMTP host
		log.Printf("Using default SMTP host: %s", config.Host)
	}
	if config.Port == "" {
		config.Port = "587" // Default SMTP port
		log.Printf("Using default SMTP port: %s", config.Port)
	}
	if config.From == "" {
		config.From = config.Username // Default sender
		log.Printf("Using username as sender: %s", config.From)
	}
	if config.AuthMethod == "" {
		config.AuthMethod = "plain" // Default to PLAIN auth
		log.Printf("Using default auth method: %s", config.AuthMethod)
	}

	// Debug output
	if config.Debug {
		log.Printf("Email config: Host=%s, Port=%s, Username=%s, UseTLS=%v, UseAuth=%v, AuthMethod=%s",
			config.Host, config.Port, config.Username, config.UseTLS, config.UseAuth, config.AuthMethod)
	}

	// Check if required credentials are present
	if config.UseAuth && (config.Username == "" || config.Password == "") {
		log.Printf("ERROR: SMTP credentials required but not configured, email notification skipped")
		return fmt.Errorf("SMTP credentials not configured")
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
	log.Printf("Connecting to SMTP server: %s", addr)

	// Create SMTP client
	var client *smtp.Client
	var err error

	if config.UseTLS {
		log.Printf("Using TLS connection")
		// Create TLS config based on whether host is IP or DNS name
		tlsConfig := getTLSConfig(config.Host)

		// Connect to the server with TLS
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			log.Printf("ERROR: TLS dial failed: %v", err)
			return fmt.Errorf("TLS dial error: %v", err)
		}

		client, err = smtp.NewClient(conn, config.Host)
		if err != nil {
			log.Printf("ERROR: SMTP client creation failed: %v", err)
			return fmt.Errorf("SMTP client error: %v", err)
		}
	} else {
		log.Printf("Using non-TLS connection")
		// Connect to the server without TLS
		client, err = smtp.Dial(addr)
		if err != nil {
			log.Printf("ERROR: SMTP dial failed: %v", err)
			return fmt.Errorf("SMTP dial error: %v", err)
		}

		// Start TLS if available
		if ok, _ := client.Extension("STARTTLS"); ok {
			log.Printf("Starting TLS via STARTTLS")
			tlsConfig := getTLSConfig(config.Host)
			if err = client.StartTLS(tlsConfig); err != nil {
				log.Printf("ERROR: STARTTLS failed: %v", err)
				return fmt.Errorf("start TLS error: %v", err)
			}
		}
	}
	defer client.Quit()

	// Authenticate if needed
	if config.UseAuth {
		log.Printf("Authenticating with method: %s", config.AuthMethod)
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
			log.Printf("ERROR: SMTP authentication failed: %v", err)
			return fmt.Errorf("SMTP authentication error: %v", err)
		}
		log.Printf("Authentication successful")
	}

	// Set the sender and recipient
	log.Printf("Setting sender: %s", config.From)
	if err = client.Mail(config.From); err != nil {
		log.Printf("ERROR: SMTP MAIL command failed: %v", err)
		return fmt.Errorf("SMTP MAIL command error: %v", err)
	}

	log.Printf("Setting recipient: %s", to)
	if err = client.Rcpt(to); err != nil {
		log.Printf("ERROR: SMTP RCPT command failed: %v", err)
		return fmt.Errorf("SMTP RCPT command error: %v", err)
	}

	// Send the email body
	log.Printf("Sending email data")
	wc, err := client.Data()
	if err != nil {
		log.Printf("ERROR: SMTP DATA command failed: %v", err)
		return fmt.Errorf("SMTP DATA command error: %v", err)
	}

	_, err = fmt.Fprint(wc, messageBody)
	if err != nil {
		log.Printf("ERROR: Writing email body failed: %v", err)
		return fmt.Errorf("SMTP body write error: %v", err)
	}

	err = wc.Close()
	if err != nil {
		log.Printf("ERROR: Closing email data failed: %v", err)
		return fmt.Errorf("SMTP data close error: %v", err)
	}

	log.Printf("SUCCESS: Email notification sent to %s", to)
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
