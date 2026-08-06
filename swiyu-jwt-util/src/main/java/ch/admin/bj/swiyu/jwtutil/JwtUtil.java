package ch.admin.bj.swiyu.jwtutil;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MLDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.experimental.UtilityClass;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

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
 * Supported key types: AKP (ML-DSA). Throws JwtUtilException for unsupported types or verification failures.
 * </p>
 */
@UtilityClass
public final class JwtUtil {

    // PQEID: ML-DSA keys don't get their own KeyType - MLDSAKey extends AKPJWK, so
    // getKeyType() returns the generic KeyType.AKP ("Algorithm Key Pair") from the
    // JOSE-PQC draft, not a per-algorithm type. MLDSAVerifier itself figures out the
    // concrete ML-DSA parameter set (44/65/87) from the JWK's own "alg" field, so a single
    // AKP -> MLDSAVerifier entry covers all of them.
    private static final Map<KeyType, Function<JWK, JWSVerifier>> VERIFIER_FACTORIES = new HashMap<>();

    static {
        VERIFIER_FACTORIES.put(KeyType.AKP, key -> {
            try {
                return new MLDSAVerifier(key.toMLDSAKey().toPublicJWK());
            } catch (JOSEException e) {
                throw new JwtUtilException("Failed to create ML-DSA verifier", e);
            }
        });
    }

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
        try {
            SignedJWT jwt = SignedJWT.parse(jwtString);
            return verifySignedJwt(jwt, keySet);
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
        try {
            JWSHeader header = jwt.getHeader();
            JWK key = keySet.getKeyByKeyId(header.getKeyID());
            if (key == null) {
                throw new JwtUtilException("No matching key found");
            }
            JWSVerifier verifier = buildVerifier(key.getKeyType(), key);
            if (!jwt.verify(verifier)) {
                throw new JwtUtilException("JWT signature verification failed");
            }
            return jwt.getJWTClaimsSet().toJSONObject();
        } catch (JOSEException | ParseException e) {
            throw new JwtUtilException("Failed to verify JWT", e);
        }
    }

    /**
     * Builds a JWSVerifier for the given key type and key.
     *
     * @param kty Key type (EC or RSA).
     * @param key JWK instance.
     * @return JWSVerifier for signature verification.
     * @throws JwtUtilException if the key type is unsupported or verifier creation fails.
     */
    public static JWSVerifier buildVerifier(KeyType kty, JWK key) throws JwtUtilException {
        Function<JWK, JWSVerifier> factory = VERIFIER_FACTORIES.get(kty);
        if (factory == null) {
            throw new JwtUtilException("Unsupported Key Type " + kty);
        }
        return factory.apply(key);
    }

}
