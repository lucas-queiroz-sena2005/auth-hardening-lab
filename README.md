# Security Project

This project is a highly secure backend application designed with strict security boundaries. 

## Architecture

- **Database:** SQLite is utilized as an atomic Data Vault.
- **Static Assets:** Nginx is used for serving Static Assets.
- **Authentication:** Local stateful Session authentication using opaque HttpOnly cookies.

## Implementation Roadmap

1. **Prototype Phase:** We will initially build a throwaway prototype in Go to establish the security boundaries and validate architectural concepts.
2. **Final Implementation:** After validation, we will migrate the project to Spring Boot for the robust, final implementation.
