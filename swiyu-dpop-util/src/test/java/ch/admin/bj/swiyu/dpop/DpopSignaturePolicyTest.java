package ch.admin.bj.swiyu.dpop;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.CompositeSigner;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** PQEID: DPoP signature check with PQ keys only, gated by DpopConstants' policy. */
class DpopSignaturePolicyTest {

    @BeforeAll
    static void registerBc() {
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
    }

    private static CompositeMLDSAKey composite() throws Exception {
        var kp = KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC").generateKeyPair();
        return CompositeMLDSAKey.fromJCA(kp.getPublic(), kp.getPrivate());
    }

    /** A DPoP proof whose header carries {@code headerJwk}, signed by {@code signer}. */
    private static SignedJWT dpop(JWSSigner signer, JWSAlgorithm alg, JWK headerJwk)
            throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(alg).type(new JOSEObjectType("dpop+jwt")).jwk(headerJwk).build(),
                new JWTClaimsSet.Builder().jwtID("j").claim("htm", "POST").build());
        jwt.sign(signer);
        return jwt;
    }

     @Test
    void compositeProof_accepted() throws Exception {
        // Arrange
        CompositeMLDSAKey key = composite();
        SignedJWT jwt = dpop(new CompositeSigner(key), JWSAlgorithm.ML_DSA_65_ES256, key.toPublicJWK());

        // Act / Assert
        assertDoesNotThrow(() -> DpopJwtValidator.validateSignature(jwt, key.toPublicJWK()));
    }

    /** The real scenario of the inherited validateSignature_invalid_throws, with an accepted key type. */
    @Test
    void acceptedKeyButWrongSignature_rejected() throws Exception {
        // Arrange: signed by A, but the header claims B's public key
        CompositeMLDSAKey a = composite();
        CompositeMLDSAKey b = composite();
        SignedJWT jwt = dpop(new CompositeSigner(a), JWSAlgorithm.ML_DSA_65_ES256, b.toPublicJWK());

        // Act / Assert
        assertThrows(DpopValidationException.class,
                () -> DpopJwtValidator.validateSignature(jwt, b.toPublicJWK()));
    }

     /** The attacker supplies the key: an algorithm outside DPoP's policy must be refused. */
    @Test
    void algorithmOutsidePolicy_rejected() throws Exception {
        // Arrange
        MLDSAKey key = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_87).generate();
        SignedJWT jwt = dpop(new MLDSASigner(key), JWSAlgorithm.ML_DSA_87, key.toPublicJWK());

        // Act / Assert
        assertThrows(DpopValidationException.class,
                () -> DpopJwtValidator.validateSignature(jwt, key.toPublicJWK()));
    }
}

