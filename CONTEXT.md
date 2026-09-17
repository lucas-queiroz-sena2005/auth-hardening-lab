# Secure Application Core

The heavily isolated, locally-authenticated backend system designed for absolute safety, managing identities and enforcing strict boundaries against the static frontend.

## Language

**Identity**:
The verified subject operating within the system after presenting valid credentials.
_Avoid_: User, Account, Principal

**Session**:
The temporary, server-side proof of an active Identity, represented by a high-entropy, opaque identifier passed strictly via secure HTTP-only cookies.
_Avoid_: JWT, Token, Auth State

**Credential**:
The securely stored secret (e.g., bcrypt/argon2 hash) used to authenticate an Identity.
_Avoid_: Password, Secret

**Security Boundary**:
The strict perimeter within the Spring application that validates the Session, sanitizes input, and enforces authorization before reaching domain logic.
_Avoid_: API, Gateway, Controller

**Static Asset**:
An untrusted, client-side resource (HTML, JS, CSS) served by Nginx that operates completely outside the Security Boundary.
_Avoid_: Frontend, Client, Web UI

**Data Vault**:
The localized, atomic SQLite storage system acting as the final source of truth, entirely shielded from any direct external or asset access.
_Avoid_: Database, DB, Storage
