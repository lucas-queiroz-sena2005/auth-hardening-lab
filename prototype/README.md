# Go Security Prototype (Atomic Data Vault & Headless Setup)

This prototype implements an atomic, hyper-secure authentication server using Go's standard library and an embedded SQLite database running in Write-Ahead Logging (WAL) mode.

## Security Features Implemented

1. **IPv6-Aware IP Rate Limiting**: Groups IPv6 requests by `/64` prefix to neutralize subnet rotation attacks.
2. **Deterministic Unicode Normalization**: Formats usernames to NFC (`norm.NFC.String`) to prevent homograph / normalization bypasses.
3. **Constant-Time Verification**:
   - Uses `subtle.ConstantTimeCompare` for system registration key verification.
   - Executes dummy bcrypt password comparisons on non-existent users to ensure identical compute cycles and prevent timing-based user enumeration.
4. **Hardened Transport Security**:
   - Strict HTTP server timeouts (`ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`) to defend against Slowloris attacks.
   - Enforces **TLS 1.3** exclusively with modern curve preferences (`X25519`, `P256`).
5. **Zero-Config Headless Execution**:
   - Automatically generates self-signed ECDSA TLS certificates (`cert.pem`, `key.pem`) on startup if missing.

---

## Running the Prototype

### Option 1: Via Nix Shell (Recommended for Local Dev)
```bash
nix-shell shell.nix
cd prototype
go run main.go
```
Access the application at `https://localhost:8443`

### Option 2: Via Docker / Docker Compose (Headless Setup)
```bash
cd prototype
docker compose up --build -d
```
Stop the container:
```bash
docker compose down
```

---

## API Testing & Endpoints

### 1. Register User (`/reg`)
```bash
curl -k -X POST https://localhost:8443/reg \
  -H "Content-Type: application/json" \
  -d '{"u":"alice", "p":"supersecurepass123", "k":"admin-key"}'
```

### 2. Login User (`/log`)
```bash
curl -k -X POST https://localhost:8443/log \
  -H "Content-Type: application/json" \
  -d '{"u":"alice", "p":"supersecurepass123"}'
```

### 3. Verify Rate Limiting (Burst 5, 1 req/sec)
Run 10 rapid requests:
```bash
for i in {1..10}; do
  curl -k -s -o /dev/null -w "%{http_code}\n" -X POST https://localhost:8443/log \
    -H "Content-Type: application/json" \
    -d '{"u":"alice", "p":"wrongpassword"}';
done
```
Notice `429` status codes after the 5th request.
