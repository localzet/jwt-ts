/*
 * Error types used by the library. These are convenience wrappers
 * around runtime errors and map to common JWT/JOSE failure modes.
 * See RFC 7519 and RFC 7515 for JWT/JWS error contexts.
 */
export class JWTError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'JWTError';
    }
}

export class InvalidSignatureError extends JWTError {
    constructor() {
        super('Invalid signature');
        this.name = 'InvalidSignatureError';
    }
}

export class TokenExpiredError extends JWTError {
    constructor() {
        super('Token expired');
        this.name = 'TokenExpiredError';
    }
}

export class NotBeforeError extends JWTError {
    constructor() {
        super('Token not active yet (nbf)');
        this.name = 'NotBeforeError';
    }
}

export class JWTClaimValidationError extends JWTError {
    constructor(message: string) {
        super(message);
        this.name = 'JWTClaimValidationError';
    }
}

export class JoseHeaderError extends JWTError {
    constructor(message: string) {
        super(message);
        this.name = 'JoseHeaderError';
    }
}
