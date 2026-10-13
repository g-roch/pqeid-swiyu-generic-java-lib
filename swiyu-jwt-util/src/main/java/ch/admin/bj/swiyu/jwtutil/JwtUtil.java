package ch.admin.bj.swiyu.jwtutil;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.experimental.UtilityClass;

import java.text.ParseException;
import java.util.Map;
import java.util.Set;

/**
 * Utility class for working with JSON Web Tokens (JWT) in the Swiyu ecosystem.
 * <p>
 * Provides static methods for signing, building headers, and verifying JWTs using ML-DSA keys.
 * All errors are unified under {@link JwtUtilException} for consistent error handling.
 * </p>
 * <ul>
 *   <li>{@link #signJwt(JWTClaimsSet, JWSHeader, JWSSigner)}: Signs a JWT with the provided claims, header, and signer.</li>
 *   <li>{@link #buildHeader(JWSAlgorithm, String, String)}: Builds a JWS header for JWT creation.</li>
 *   <li>{@link #verifyJwt(String, JWKSet)}: Verifies a JWT string using a JWKSet and returns its claims.</li>
 *   <li>{@link #verifySignedJwt(SignedJWT, JWKSet)}: Verifies a SignedJWT using a JWKSet and returns its claims.</li>
 *   <li>{@link #buildVerifier(KeyType, JWK)}: Builds a JWSVerifier for the given key type and key.</li>
 * </ul>
 * <p>
 * Supported key types: AKP (ML-DSA and composite ML-DSA-65-ES256, gated by an algorithm policy). 
 * Throws JwtUtilException for unsupported types or verification failures.
 * </p>
 */
@UtilityClass
public final class JwtUtil {

    /**
     * Signs a JWT with the provided claims, header, and signer.
     *
     * @param claimsSet JWT claims to include in the token.
     * @param header JWS header specifying algorithm and key ID.
     * @param signer JWSSigner instance for signing.
     * @return SignedJWT object.
     * @throws JwtUtilException if signing fails.
     */
    public static SignedJWT signJwt(JWTClaimsSet claimsSet, JWSHeader header, JWSSigner signer)
            throws JwtUtilException {
        try {
            SignedJWT signedJwt = new SignedJWT(header, claimsSet);
            signedJwt.sign(signer);
            return signedJwt;
        } catch (JOSEException e) {
            throw new JwtUtilException("Failed to sign JWT", e);
        }
    }

    /**
     * Builds a JWS header for JWT creation.
     *
     * @param algorithm JWS algorithm (e.g., ES256, RS256).
     * @param keyId Key identifier.
     * @param typ Token type (e.g., "JWT").
     * @return JWSHeader instance.
     */
    public static JWSHeader buildHeader(JWSAlgorithm algorithm, String keyId, String typ) {
        return new JWSHeader.Builder(algorithm)
                .keyID(keyId)
                .type(new JOSEObjectType(typ))
                .build();
    }

    /**
     * Verifies a JWT string using the provided JWKSet.
     *
     * @param jwtString JWT as a string.
     * @param keySet JWKSet containing public keys for verification.
     * @return Claims map extracted from the JWT.
     * @throws JwtUtilException if parsing or verification fails.
     */
    public static Map<String, Object> verifyJwt(String jwtString, JWKSet keySet)
            throws JwtUtilException {
        return verifyJwt(jwtString, keySet, SignatureVerifiers.MIGRATION_DEFAULT);
    }

     /** PQEID: verifies only algorithms in {@code accepted} (policy). */
    public static Map<String, Object> verifyJwt(String jwtString, JWKSet keySet,
                                                Set<JWSAlgorithm> accepted) throws JwtUtilException {
        try {
            return verifySignedJwt(SignedJWT.parse(jwtString), keySet, accepted);
        } catch (ParseException e) {
            throw new JwtUtilException("Failed to parse JWT", e);
        }
    }

    /**
     * Verifies a SignedJWT using the provided JWKSet.
     *
     * @param jwt SignedJWT object.
     * @param keySet JWKSet containing public keys for verification.
     * @return Claims map extracted from the JWT.
     * @throws JwtUtilException if verification fails.
     */
    public static Map<String, Object> verifySignedJwt(SignedJWT jwt, JWKSet keySet)
            throws JwtUtilException {
         return verifySignedJwt(jwt, keySet, SignatureVerifiers.MIGRATION_DEFAULT);
    }

    /** PQEID: verifies only algorithms in {@code accepted} (policy). */
    public static Map<String, Object> verifySignedJwt(SignedJWT jwt, JWKSet keySet,
                                                      Set<JWSAlgorithm> accepted) throws JwtUtilException {
        try {
            JWSHeader header = jwt.getHeader();
            JWK key = keySet.getKeyByKeyId(header.getKeyID());
            if (key == null) {
                throw new JwtUtilException("No matching key found");
            }
            JWSVerifier verifier = SignatureVerifiers.forKey(key, header.getAlgorithm(), accepted);
            if (!jwt.verify(verifier)) {
                throw new JwtUtilException("JWT signature verification failed");
            }
            return jwt.getJWTClaimsSet().toJSONObject();
        } catch (JOSEException | ParseException e) {
            throw new JwtUtilException("Failed to verify JWT", e);
        }
    }

    /**
     * @deprecated PQEID: has no header alg, so the policy can only use the key's own alg.
     * Use {@link SignatureVerifiers#forKey} with the JWS header's alg instead.
     */
    @Deprecated
    public static JWSVerifier buildVerifier(KeyType kty, JWK key) throws JwtUtilException {
        if (!KeyType.AKP.equals(kty) || !(key.getAlgorithm() instanceof JWSAlgorithm alg)) {
            throw new JwtUtilException("Unsupported Key Type " + kty);
        }
        return SignatureVerifiers.forKey(key, alg, SignatureVerifiers.MIGRATION_DEFAULT);
    }
}
