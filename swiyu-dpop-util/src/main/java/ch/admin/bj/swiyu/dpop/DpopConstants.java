package ch.admin.bj.swiyu.dpop;

import  com.nimbusds.jose.JWSAlgorithm;

import java.util.stream.Collectors;

import java.util.Set;
import java.util.List;

/**
 * Constants and defaults for DPoP validation.
 * <p>
 * Provides standard values for DPoP JWT header and payload claims, supported algorithms, and other
 * configuration used throughout the DPoP validation process.
 * </p>
 */
public final class DpopConstants {

    /**
     * The required 'typ' header value for DPoP JWTs.
     */
    public static final String DPOP_JWT_HEADER_TYP = "dpop+jwt";

    /**
     * Supported algorithms for DPoP JWT signatures.
     */
    public static final List<String> SUPPORTED_ALGORITHMS = List.of("ML-DSA-44", "ML-DSA-65-ES256");


     /** The same policy, as nimbus algorithms (used by DpopJwtValidator.validateSignature). */
    public static final Set<JWSAlgorithm> SUPPORTED_JWS_ALGORITHMS = SUPPORTED_ALGORITHMS.stream()
            .map(JWSAlgorithm::parse).collect(Collectors.toUnmodifiableSet());

    /**
     * Mandatory header claims for DPoP JWTs.
     */
    public static final List<String> MANDATORY_HEADER_CLAIMS = List.of("typ", "alg", "jwk");

    /**
     * Mandatory payload claims for DPoP JWTs.
     */
    public static final List<String> MANDATORY_PAYLOAD_CLAIMS = List.of("jti", "htm", "htu", "iat", "nonce");

    /**
     * Private constructor to prevent instantiation.
     */
    private DpopConstants() {
    }
}
