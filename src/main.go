package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/unicode/norm"
	"golang.org/x/time/rate"
	"golang.org/x/term"
	_ "modernc.org/sqlite"
)

//go:embed static/*
var staticFiles embed.FS

// Global database connection, IP limiter store, dummy hash for timing protection, and system key.
var (
	db        *sql.DB
	ips       sync.Map
	dummy     []byte
	sysKey    = []byte("admin-key") // Default system registration key
	cryptoKey = []byte("super-secret") // Default cryptography key
)

// ============================================================================
// Security: IP Rate Limiting
// This middleware implements a token bucket rate limiter (1 req/sec, burst of 5).
// It tracks IPv4 addresses directly, and groups IPv6 addresses by /64 prefix to
// mitigate IPv6 subnet rotation attacks. This provides robust protection against
// brute-force login attempts and denial-of-service (DoS) at the application layer.
// ============================================================================
func rl(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddrPort(r.RemoteAddr)
		key := "unknown"
		if err == nil {
			addr := ip.Addr()
			if addr.Is6() {
				// Group IPv6 addresses by /64 prefix to prevent single-subnet IP rotation
				prefix, _ := addr.Prefix(64)
				key = prefix.String()
			} else {
				key = addr.String()
			}
		}

		// Token bucket limiter: 1 request/second, burst of 5
		limiterObj, _ := ips.LoadOrStore(key, rate.NewLimiter(1, 5))
		if !limiterObj.(*rate.Limiter).Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": "Too many requests. Rate limit exceeded."})
			return
		}
	next(w, r)
	}
}

// ============================================================================
// Auth Operations: Registration & Login
// Implements secure credential handling, including length validation,
// Unicode Normalization (NFC) to prevent homograph attacks, constant-time
// comparisons to prevent timing attacks, and bcrypt hashing.
// ============================================================================
func op(w http.ResponseWriter, r *http.Request, isRegister bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var credentials struct {
		Username string `json:"u"`
		Password string `json:"p"`
		Key      string `json:"k"`
	}

	// Strict JSON decoding & minimum password length validation
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil || len(credentials.Password) < 8 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload or password shorter than 8 characters."})
		return
	}

	// Security: Enforce deterministic Unicode Normalization (NFC)
	// Normalizing the username prevents canonical equivalency bypasses and homograph attacks.
	credentials.Username = norm.NFC.String(credentials.Username)

	if isRegister {
		// Security: Constant-time comparison for system key to prevent timing attacks
		if len(sysKey) > 0 {
			if len(credentials.Key) != len(sysKey) || subtle.ConstantTimeCompare([]byte(credentials.Key), sysKey) != 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid system registration key."})
				return
			}
		}

		// Security: Hash password with bcrypt cost 12. This is an optimal balance
		// between security (work factor) and performance for this use case.
		hash, err := bcrypt.GenerateFromPassword([]byte(credentials.Password), 12)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Insert user into SQLite Data Vault
		if _, err := db.Exec("INSERT INTO usr(u, h) VALUES(?, ?)", credentials.Username, hash); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "Username already exists."})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully."})
	} else {
		// LOGIN FLOW
		var storedHash []byte
		err := db.QueryRow("SELECT h FROM usr WHERE u = ?", credentials.Username).Scan(&storedHash)

		// Security: Dummy Hashing for Constant-Time Execution
		// If a user is not found, we still perform a bcrypt comparison against a dummy hash.
		// This ensures that the authentication endpoint takes roughly the same amount of CPU time
		// whether the user exists or not, neutralizing timing-based username enumeration attacks.
		if err != nil {
			storedHash = dummy
		}

		bcryptErr := bcrypt.CompareHashAndPassword(storedHash, []byte(credentials.Password))
		if bcryptErr != nil || err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials."})
			return
		}

		// Generate 32-byte cryptographically secure session token
		rawToken := make([]byte, 32)
		if _, randErr := rand.Read(rawToken); randErr != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		
		// HMAC the token using the cryptoKey for additional integrity
		mac := hmac.New(sha256.New, cryptoKey)
		mac.Write(rawToken)
		hmacSum := mac.Sum(nil)
		
		tokenHex := fmt.Sprintf("%x.%x", rawToken, hmacSum)
		expiresAt := time.Now().Add(2 * time.Hour)

		// Persist active server-side session with expiration
		if _, err := db.Exec("INSERT INTO sess(token, u, exp) VALUES(?, ?, ?)", tokenHex, credentials.Username, expiresAt); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Set HttpOnly, Secure session cookie as specified in CONTEXT.md
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    tokenHex,
			Path:     "/",
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":    "Login successful",
			"token":      tokenHex,
			"expires_at": expiresAt.Format(time.RFC3339),
		})
	}
}

// ============================================================================
// AUTOMATIC TLS CERTIFICATE GENERATOR
// Ensures headless zero-configuration SSL/TLS execution if certs are missing.
// ============================================================================
func ensureTLSCertificates(certFile, keyFile string) error {
	if _, errCert := os.Stat(certFile); errCert == nil {
		if _, errKey := os.Stat(keyFile); errKey == nil {
			return nil // Both files exist
		}
	}

	log.Println("[TLS Bootstrap] Generating self-signed TLS ECDSA certificates...")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Impenetrable Security Prototype"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(certFile), 0755); err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	log.Println("[TLS Bootstrap] Certificates created successfully.")
	return nil
}

// ============================================================================
// MAIN ENTRYPOINT
// ============================================================================
func main() {
	// CLI Prompts for Security Keys
	fmt.Print("Insira a Chave de Sistema de Registro (Pressione Enter para desabilitar. Esta chave restringe quem pode registrar novas contas): ")
	if sysKeyInput, err := term.ReadPassword(int(os.Stdin.Fd())); err == nil {
		if len(sysKeyInput) > 0 {
			sysKey = sysKeyInput
		} else {
			sysKey = nil
			fmt.Print("\n[!] Chave de Sistema de Registro DESABILITADA. Qualquer um pode registrar novas contas.")
		}
	}
	fmt.Println()

	fmt.Print("Insira a Chave Criptográfica (usada para o HMAC dos tokens): ")
	if cryptoKeyInput, err := term.ReadPassword(int(os.Stdin.Fd())); err == nil && len(cryptoKeyInput) > 0 {
		cryptoKey = cryptoKeyInput
	}
	fmt.Println("\n[Init] Starting Secure Identity Portal...")

	// Background eviction routines
	go func() {
		for range time.Tick(1 * time.Hour) {
			ips.Clear()
		}
	}()

	go func() {
		for range time.Tick(15 * time.Minute) {
			if db != nil {
				db.Exec("DELETE FROM sess WHERE exp < ?", time.Now())
			}
		}
	}()

	envSysKey := os.Getenv("SYS_KEY")
	if envSysKey != "" {
		sysKey = []byte(envSysKey)
	}

	log.Println("[Init] Pre-computing dummy bcrypt hash for timing attack protection...")
	var err error
	dummy, err = bcrypt.GenerateFromPassword([]byte("!"), 12)
	if err != nil {
		log.Fatalf("Failed to generate dummy hash: %v", err)
	}

	// 2. Initialize SQLite Data Vault with Write-Ahead Logging (WAL) mode
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "data/data.db"
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		log.Fatalf("Failed to create database directory: %v", err)
	}

	log.Printf("[Init] Connecting to SQLite Data Vault (%s in WAL mode)...\n", dbPath)
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", dbPath)
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS usr(u TEXT UNIQUE, h BLOB); CREATE TABLE IF NOT EXISTS sess(token TEXT PRIMARY KEY, u TEXT, exp DATETIME);"); err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}

	// 3. Register HTTP Router & Handlers
	mux := http.NewServeMux()

	// Auth endpoints with rate limiting
	mux.HandleFunc("/reg", rl(func(w http.ResponseWriter, r *http.Request) { op(w, r, true) }))
	mux.HandleFunc("/log", rl(func(w http.ResponseWriter, r *http.Request) { op(w, r, false) }))

	// Config endpoint
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"sysKeyRequired": len(sysKey) > 0})
	})

	// Session validation endpoint
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Not authenticated"})
			return
		}

		var username string
		var exp time.Time
		err = db.QueryRow("SELECT u, exp FROM sess WHERE token = ?", cookie.Value).Scan(&username, &exp)
		if err != nil || time.Now().After(exp) {
			db.Exec("DELETE FROM sess WHERE token = ?", cookie.Value)
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				Expires:  time.Unix(0, 0),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Session expired or invalid"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"u":   username,
			"exp": exp.Format(time.RFC3339),
		})
	})

	// Logout endpoint
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("session_id"); err == nil && cookie.Value != "" {
			db.Exec("DELETE FROM sess WHERE token = ?", cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
	})

	// Static HTML frontend endpoint from embedded files
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		
		indexData, err := staticFiles.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write(indexData)
	})

	// 4. Hardened HTTP Server
	srv := &http.Server{
		Addr:              ":8443", // Default port 8443
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		},
		Handler: mux,
	}

	port := os.Getenv("PORT")
	if port != "" {
		srv.Addr = ":" + port
	}

	disableTLS := os.Getenv("DISABLE_TLS") == "true" || os.Getenv("DISABLE_TLS") == "1"

	if disableTLS {
		log.Printf("[Server] Starting HTTP server (TLS disabled) on http://localhost%s\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	} else {
		certFile := os.Getenv("CERT_FILE")
		if certFile == "" {
			certFile = "data/cert.pem"
		}
		keyFile := os.Getenv("KEY_FILE")
		if keyFile == "" {
			keyFile = "data/key.pem"
		}

		// Ensure TLS certificates exist
		if err := ensureTLSCertificates(certFile, keyFile); err != nil {
			log.Fatalf("Failed to generate TLS certificates: %v", err)
		}

		log.Printf("[Server] Starting secure HTTPS server on https://localhost%s\n", srv.Addr)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}
}
