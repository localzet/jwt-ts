# @localzet/jwt

A canonical, minimal-dependency JWT library in TypeScript.

Features implemented:
- JWS signing and verification (compact serialization)
- Signing algorithms: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, EdDSA. The unsigned `none` algorithm is **not accepted by verification**.
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


## Verification safety

`verify()`, `verifyCompact()` and `verifyGeneral()` reject unsecured `alg: none` tokens. General JWS requires at least one signature and forbids a duplicate header parameter across protected and unprotected fields. Public-key lookup functions should select a key according to a trusted allowlist and the expected algorithm, not solely untrusted token fields. `decode()` only parses data and does **not** authenticate it.

These checks are covered by `npm test` and the Node 22/24 GitHub Actions matrix. This library is not an external cryptographic certification; review the full JOSE threat model before using it as the sole authorization control.
