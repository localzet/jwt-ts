/*
 * Public exports for the library. Keep the public surface small and focused.
 */
export * from './jwt';
export * from './jwa';
export * from './errors';
export * from './jwk';
export * from './jws';
export * from './jwe';
export * from './jwks';

// Export canonical classes (OOP API)
export { JWTService, jwtService } from './jwt';
export { JWSService, jwsService } from './jws';
export { JWEService, jweService } from './jwe';
export { JWKManager, jwkManager } from './jwk';
export { JWAFactory, jwa } from './jwa';
export { HeaderValidator } from './header';
export { JWKSResolver, jwksResolver } from './jwks';
