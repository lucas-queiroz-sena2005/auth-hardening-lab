package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) {
	var err error
	dummy, err = bcrypt.GenerateFromPassword([]byte("!"), 12)
	if err != nil {
		t.Fatalf("Failed to generate dummy hash: %v", err)
	}

	dbFile := "test_data.db"
	os.Remove(dbFile)

	db, err = sql.Open("sqlite", "file:"+dbFile+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS usr(u TEXT UNIQUE, h BLOB); CREATE TABLE IF NOT EXISTS sess(token TEXT PRIMARY KEY, u TEXT, exp DATETIME);"); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
		os.Remove(dbFile)
	})
}

func TestRegistrationAndLoginFlow(t *testing.T) {
	setupTestDB(t)

	// 1. Test Registration with valid credentials
	regBody, _ := json.Marshal(map[string]string{
		"u": "alice",
		"p": "supersecretpassword123",
		"k": "admin-key",
	})
	reqReg := httptest.NewRequest(http.MethodPost, "/reg", bytes.NewBuffer(regBody))
	reqReg.RemoteAddr = "127.0.0.1:12345"
	rrReg := httptest.NewRecorder()

	op(rrReg, reqReg, true)

	if status := rrReg.Code; status != http.StatusCreated {
		t.Errorf("Registration failed: got status %v, want %v. Body: %s", status, http.StatusCreated, rrReg.Body.String())
	}

	// 2. Test Registration duplicate user -> Should return 409 Conflict
	rrDup := httptest.NewRecorder()
	op(rrDup, httptest.NewRequest(http.MethodPost, "/reg", bytes.NewBuffer(regBody)), true)
	if status := rrDup.Code; status != http.StatusConflict {
		t.Errorf("Duplicate registration failed: got status %v, want %v", status, http.StatusConflict)
	}

	// 3. Test Registration invalid key -> Should return 403 Forbidden
	invalidKeyBody, _ := json.Marshal(map[string]string{
		"u": "bob",
		"p": "supersecretpassword123",
		"k": "wrong-key",
	})
	rrInvalidKey := httptest.NewRecorder()
	op(rrInvalidKey, httptest.NewRequest(http.MethodPost, "/reg", bytes.NewBuffer(invalidKeyBody)), true)
	if status := rrInvalidKey.Code; status != http.StatusForbidden {
		t.Errorf("Invalid key registration failed: got status %v, want %v", status, http.StatusForbidden)
	}

	// 4. Test Login with correct credentials -> Should return 200 OK
	loginBody, _ := json.Marshal(map[string]string{
		"u": "alice",
		"p": "supersecretpassword123",
	})
	reqLogin := httptest.NewRequest(http.MethodPost, "/log", bytes.NewBuffer(loginBody))
	reqLogin.RemoteAddr = "127.0.0.1:12346"
	rrLogin := httptest.NewRecorder()

	op(rrLogin, reqLogin, false)

	if status := rrLogin.Code; status != http.StatusOK {
		t.Errorf("Login failed: got status %v, want %v. Body: %s", status, http.StatusOK, rrLogin.Body.String())
	}

	// 5. Test Login with incorrect password -> Should return 401 Unauthorized
	wrongPassBody, _ := json.Marshal(map[string]string{
		"u": "alice",
		"p": "wrongpassword123",
	})
	rrWrongPass := httptest.NewRecorder()
	op(rrWrongPass, httptest.NewRequest(http.MethodPost, "/log", bytes.NewBuffer(wrongPassBody)), false)
	if status := rrWrongPass.Code; status != http.StatusUnauthorized {
		t.Errorf("Wrong password login failed: got status %v, want %v", status, http.StatusUnauthorized)
	}

	// 6. Test Login with non-existent user -> Should return 401 Unauthorized (dummy hash path)
	nonExistentBody, _ := json.Marshal(map[string]string{
		"u": "nonexistentuser",
		"p": "somepassword123",
	})
	rrNonExistent := httptest.NewRecorder()
	op(rrNonExistent, httptest.NewRequest(http.MethodPost, "/log", bytes.NewBuffer(nonExistentBody)), false)
	if status := rrNonExistent.Code; status != http.StatusUnauthorized {
		t.Errorf("Non-existent user login failed: got status %v, want %v", status, http.StatusUnauthorized)
	}
}
