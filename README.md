# zkDPoP-Go

A Golang framework for zero-knowledge Demonstration of Proof-of-Possession (zkDPoP) authentication using interactive Schnorr signatures with sender-constrained JWTs.

## Features

- Interactive Schnorr ZK login over secp256k1 or ristretto255
- Issues short-lived, DPoP-bound JWTs (5-15 minutes)
- Sender-constrained tokens via `cnf.jkt` binding to DPoP keys
- Per-request DPoP verification middleware
- Stateless resource servers (validate JWT + DPoP without ZK knowledge)
- Clean extension points for broader ZK authorization
- Comprehensive security hardening (replay protection, tight windows, configurable rate limits)

## Architecture

```
+------------------+          +---------------------+         +-------------------+
|  Client          |          |  Auth Server        |         |  Resource Server  |
|  (DPoP keypair)  |          |  (zkDPoP AuthZ)     |         |  (API + middleware)|
+---------+--------+          +----------+----------+         +---------+---------+
          |                               |                              |
(1) POST /auth/zk/commit  DPoP proof ---> |                              |
          | <--- (2) c, timeslice, server_ephemeral                      |
(3) POST /auth/zk/complete  + s  DPoP --->|  verify schnorr & DPoP       |
          | <--- (4) JWT {cnf.jkt=thumb(DPoP JWK)}                       |
          |                               |                              |
          | --- API call --- DPoP + JWT -------------------------------> | verify DPoP + JWT
          |                               |                              |
```

## Quick Start

```bash
# Start auth server
go run ./cmd/zkdpop-authd

# Start demo API server  
go run ./cmd/zkdpop-demo-api

# Run example client
go run ./examples/client-go

# Use the Ristretto255 group instead of secp256k1
go run ./cmd/zkdpop-authd --curve ristretto255
go run ./examples/client-go --curve ristretto255
```

Both servers expose a `--rate-limit` flag (requests per minute per client). The default of `120` for the authd binary and `240` for the demo API keeps login flows responsive while guarding against brute-force attempts.

## Project Structure

- `cmd/zkdpop-authd` - Reference auth server
- `cmd/zkdpop-demo-api` - Example resource server
- `pkg/crypto/` - Curve interfaces and Schnorr verification
- `pkg/dpop/` - DPoP proof verification and JWK thumbprints
- `pkg/jwt/` - JWT minting/verification with cnf.jkt binding
- `pkg/auth/` - Auth handlers for ZK login endpoints
- `pkg/storage/` - Storage interfaces and implementations
- `pkg/middleware/` - HTTP middleware for DPoP and JWT verification
- `examples/client-go/` - Sample client implementation

## Standards Compliance

- [RFC 9449 - DPoP](https://datatracker.ietf.org/doc/html/rfc9449) - Demonstration of Proof-of-Possession
- [RFC 7800 - JWT Proof-of-Possession](https://datatracker.ietf.org/doc/html/rfc7800) - `cnf.jkt` binding
- [RFC 7638 - JWK Thumbprints](https://datatracker.ietf.org/doc/html/rfc7638) - JWK SHA-256 thumbprints

## License

MIT
