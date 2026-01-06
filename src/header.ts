/*
 * JOSE header validation helpers.
 * Enforces known header parameters, `crit` processing and basic `cty`/`typ` semantics.
 * References: RFC 7515 (JWS), RFC 7516 (JWE), RFC 7519 (JWT) for header semantics.
 */
import { JoseHeaderError } from './errors';

export type JoseContext = 'jws' | 'jwe' | 'jwt';

export interface HeaderValidationOptions {
    context: JoseContext;
    enforceUnknown?: 'reject' | 'ignore';
    allowedExtensions?: Set<string>;
    expectedTyp?: string | null;
}

const COMMON: Set<string> = new Set(['alg', 'kid', 'typ', 'cty', 'jku', 'jwk', 'x5u', 'x5c', 'x5t', 'x5t#S256', 'crit']);
const JWS_ONLY: Set<string> = new Set(['b64']);
const JWE_ONLY: Set<string> = new Set(['enc', 'epk', 'apu', 'apv', 'iv', 'tag', 'zip', 'cek', 'encrypted_key']);

function allowedParamsFor(context: JoseContext): Set<string> {
    const s = new Set<string>(COMMON);
    if (context === 'jws') {
        for (const k of JWS_ONLY) s.add(k);
    }
    if (context === 'jwe') {
        for (const k of JWE_ONLY) s.add(k);
    }
    return s;
}

export function validateJoseHeaders(header: { [k: string]: any } | undefined, opts: HeaderValidationOptions) {
    return HeaderValidator.validate(header, opts);
}

export class HeaderValidator {
    static validate(header: { [k: string]: any } | undefined, opts: HeaderValidationOptions) {
        if (!header) return;
        if (typeof header !== 'object') throw new JoseHeaderError('JOSE header must be an object');

        const allowed = allowedParamsFor(opts.context);
        const allowedExt = opts.allowedExtensions || new Set<string>();
        const enforceUnknown = opts.enforceUnknown ?? 'ignore';

        if (header.crit !== undefined) {
            if (!Array.isArray(header.crit) || !header.crit.every((i: any) => typeof i === 'string')) {
                throw new JoseHeaderError('Invalid "crit" header: must be array of strings');
            }
            for (const critName of header.crit as string[]) {
                if (!Object.prototype.hasOwnProperty.call(header, critName)) {
                    throw new JoseHeaderError(`crit declares ${critName} but it is not present in header`);
                }
                if (!allowed.has(critName) && !allowedExt.has(critName)) {
                    throw new JoseHeaderError(`Unsupported critical header parameter: ${critName}`);
                }
            }
        }

        for (const k of Object.keys(header)) {
            if (allowed.has(k)) continue;
            if (allowedExt.has(k)) continue;
            if (k === 'x5t#S256') continue;
            if (enforceUnknown === 'reject') {
                throw new JoseHeaderError(`Unknown JOSE header parameter: ${k}`);
            }
        }

        if (opts.expectedTyp) {
            if (header.typ !== undefined && header.typ !== opts.expectedTyp) {
                throw new JoseHeaderError(`Unexpected typ header: expected ${opts.expectedTyp}`);
            }
        }

        if (header.cty !== undefined && typeof header.cty !== 'string') {
            throw new JoseHeaderError('cty header must be a string when present');
        }
    }
}
