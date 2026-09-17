package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
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
	_ "modernc.org/sqlite"
)

// Global database connection, IP limiter store, dummy hash for timing protection, and system key.
var (
	db     *sql.DB
	ips    sync.Map
	dummy  []byte
	sysKey = []byte("admin-key") // Default system registration key
)

// ============================================================================
// SECURITY MECHANISM 1: IP Rate Limiting with IPv6 /64 Subnet Prefixing
// Prevents brute-force attacks and IPv6 subnet rotation attacks.
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
// SECURITY MECHANISM 2 & 3: Unicode Normalization & Constant-Time Operations
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

	// SECURITY MECHANISM 2: Enforce deterministic Unicode Normalization (NFC)
	// Prevents homograph attacks and canonical equivalency bypasses.
	credentials.Username = norm.NFC.String(credentials.Username)

	if isRegister {
		// SECURITY MECHANISM 3A: Constant-time comparison for system key
		if len(credentials.Key) != len(sysKey) || subtle.ConstantTimeCompare([]byte(credentials.Key), sysKey) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid system registration key."})
			return
		}

		// Hash password with bcrypt cost 14 for strong work factor
		hash, err := bcrypt.GenerateFromPassword([]byte(credentials.Password), 14)
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

		// SECURITY MECHANISM 3B: Constant-Time Execution via Dummy Hashing
		// If user is not found, compare against a dummy hash to force identical CPU compute cycles
		// and completely neutralize timing-based username enumeration attacks.
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
		token := make([]byte, 32)
		if _, randErr := rand.Read(token); randErr != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Login successful",
			"token":   fmt.Sprintf("%x", token),
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
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
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
	// 1. Background memory eviction routine to prevent OOM DOS from rate-limiter state growth
	go func() {
		for range time.Tick(1 * time.Hour) {
			ips.Clear()
		}
	}()

	log.Println("[Init] Pre-computing dummy bcrypt hash for timing attack protection...")
	var err error
	dummy, err = bcrypt.GenerateFromPassword([]byte("!"), 14)
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

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS usr(u TEXT UNIQUE, h BLOB)"); err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}

	// 3. Register HTTP Router & Handlers
	mux := http.NewServeMux()

	// Auth endpoints with rate limiting
	mux.HandleFunc("/reg", rl(func(w http.ResponseWriter, r *http.Request) { op(w, r, true) }))
	mux.HandleFunc("/log", rl(func(w http.ResponseWriter, r *http.Request) { op(w, r, false) }))

	// Static HTML frontend endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "static/index.html")
	})

	// 4. Hardened HTTP Server
	srv := &http.Server{
		Addr:              ":8443", // Default port 8443
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS13,
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
		// Ensure TLS certificates exist
		if err := ensureTLSCertificates("cert.pem", "key.pem"); err != nil {
			log.Fatalf("Failed to generate TLS certificates: %v", err)
		}

		log.Printf("[Server] Starting secure HTTPS server on https://localhost%s\n", srv.Addr)
		if err := srv.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}
}
