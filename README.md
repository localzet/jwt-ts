# fjwt

A canonical, minimal-dependency JWT library in TypeScript.

Features implemented:
- JWS signing and verification (compact serialization)
- Algorithms: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, none
- Base64url encoding helpers
- Claim validation for `exp`, `nbf`, `iat`, `iss`, `aud`
- Minimal dependencies (Node's built-in `crypto`)

Quick start:

1. Install dev dependencies:

```bash
npm install
```

2. Build:

```bash
npm run build
```

3. Run example:

```bash
npm run test
```

API:
- `sign(payload, key, options)` -> Promise<string>
- `verify(token, key, options)` -> Promise<object>
- `decode(token, {complete})`


Notes:
- For RSA/ECDSA signing/verifying provide keys in PEM format (private key for sign, public key for verify).
- ECDSA handling converts between DER and JOSE signatures to comply with JWT format.
