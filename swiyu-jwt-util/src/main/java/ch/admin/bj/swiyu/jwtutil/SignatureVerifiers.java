package ch.admin.bj.swiyu.jwtutil;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.CompositeVerifier;
import com.nimbusds.jose.crypto.MLDSAVerifier;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.MLDSAKey;

import java.util.Set;

/**
 * PQEID crypto agility: picks the JWS verifier from the key type, but only for an
 * algorithm the caller's POLICY accepts. Neither the token nor the key
 * alone may choose the algorithm: an attacker can supply both (holder key, DPoP header JWK).
 */
public final class SignatureVerifiers {

    /** Expand phase of the migration: ML-DSA-44 (current keys) and the hybrid composite. */
    public static final Set<JWSAlgorithm> MIGRATION_DEFAULT =
            Set.of(JWSAlgorithm.ML_DSA_44, JWSAlgorithm.ML_DSA_65_ES256);

    private SignatureVerifiers() {
    }

    /**
     * @param key       the key to verify with (a private key is reduced to its public part)
     * @param headerAlg the {@code alg} of the JWS being verified
     * @param accepted  the algorithms this caller accepts (policy)
     * @return a verifier for exactly that key and algorithm
     * @throws JwtUtilException if the algorithm is not accepted, doesn't match the key,
     *                          or the key type is not supported
     */
    public static JWSVerifier forKey(JWK key, JWSAlgorithm headerAlg, Set<JWSAlgorithm> accepted) {
        if (key == null || headerAlg == null || accepted == null) {
            throw new JwtUtilException("key, header alg and accepted algorithms are required");
        }
        if (!accepted.contains(headerAlg)) {
            throw new JwtUtilException("JWS algorithm " + headerAlg
                    + " is not accepted (accepted: " + accepted + ")");
        }
        if (!headerAlg.equals(key.getAlgorithm())) {
            throw new JwtUtilException("JWS algorithm " + headerAlg
                    + " does not match the key's algorithm " + key.getAlgorithm());
        }
                try {
            if (key instanceof MLDSAKey k) {
                return new MLDSAVerifier(k.toPublicJWK());
            }
            if (key instanceof CompositeMLDSAKey k) {
                return new CompositeVerifier(k.toPublicJWK());
            }
        } catch (JOSEException e) {
            throw new JwtUtilException("Failed to create a verifier for " + headerAlg, e);
        }
        throw new JwtUtilException("Unsupported key type for signatures: " + key.getKeyType());
    }
}
