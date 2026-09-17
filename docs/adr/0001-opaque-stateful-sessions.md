# ADR 0001: Opaque Stateful Sessions

## Context
We need a highly secure mechanism for authenticating users and maintaining session state. The choice often comes down to stateless JWTs (JSON Web Tokens) or traditional stateful sessions.

## Decision
We have decided to use **opaque stateful sessions** over stateless JWTs. 
Session identifiers will be stored in secure, HttpOnly cookies on the client side, while the actual session data will be stored securely in the SQLite database (the Data Vault).

## Rationale
- **Immediate Revocability:** Stateful sessions allow us to instantly invalidate a session on the server side, mitigating risks associated with compromised tokens or sudden account compromises.
- **Security First:** We are prioritizing maximum security and revocability over horizontal scalability. The ability to guarantee that a revoked session cannot be used is paramount.
- **Simplicity:** Managing stateful sessions in a single Data Vault simplifies the security model compared to complex token blacklisting mechanisms required for JWTs.

## Consequences
- Requires database access (SQLite) to validate the session on every authenticated request.
- Horizontal scaling might require more complex session management (e.g., sticky sessions or a distributed session store if SQLite becomes a bottleneck), although this is deemed an acceptable trade-off for the security benefits at this stage.
