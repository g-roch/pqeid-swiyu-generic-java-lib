package ch.admin.bj.swiyu.jwtutil;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.CompositeSigner;
import com.nimbusds.jose.crypto.CompositeVerifier;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.crypto.MLDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Set;

import static com.nimbusds.jose.JWSAlgorithm.ML_DSA_44;
import static com.nimbusds.jose.JWSAlgorithm.ML_DSA_65_ES256;
import static com.nimbusds.jose.JWSAlgorithm.ML_DSA_87;
import static org.junit.jupiter.api.Assertions.*;

/** PQEID: verifier chosen by key type, gated by an explicit algorithm policy. */
class SignatureVerifiersTest {

    private static final Set<JWSAlgorithm> POLICY = SignatureVerifiers.MIGRATION_DEFAULT;

    @BeforeAll
    static void registerBc() {
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
    }

    private static MLDSAKey mldsa(JWSAlgorithm alg) throws Exception {
        return new MLDSAKeyGenerator(alg).generate();
    }

    private static CompositeMLDSAKey composite() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC")
                .generateKeyPair();
        return CompositeMLDSAKey.fromJCA(kp.getPublic(), kp.getPrivate());
    }

    private static JWSObject signed(JWSSigner signer, JWSAlgorithm alg) throws Exception {
        JWSObject jws = new JWSObject(new JWSHeader(alg), new Payload("hello"));
        jws.sign(signer);
        return jws;
    }

    @Test
    void mldsa44_accepted_andVerifies() throws Exception {
        MLDSAKey key = mldsa(ML_DSA_44);
        JWSObject jws = signed(new MLDSASigner(key), ML_DSA_44);

        JWSVerifier v = SignatureVerifiers.forKey(key.toPublicJWK(), ML_DSA_44, POLICY);

        assertInstanceOf(MLDSAVerifier.class, v);
        assertTrue(jws.verify(v));
    }

    @Test
    void composite_accepted_andVerifies() throws Exception {
        CompositeMLDSAKey key = composite();
        JWSObject jws = signed(new CompositeSigner(key), ML_DSA_65_ES256);

        JWSVerifier v = SignatureVerifiers.forKey(key.toPublicJWK(), ML_DSA_65_ES256, POLICY);

        assertInstanceOf(CompositeVerifier.class, v);
        assertTrue(jws.verify(v));
    }

     /** An attacker-supplied key must not choose an algorithm outside the policy. */
    @Test
    void algorithmOutsidePolicy_rejected() throws Exception {
        MLDSAKey key = mldsa(ML_DSA_87);
        assertThrows(JwtUtilException.class,
                () -> SignatureVerifiers.forKey(key.toPublicJWK(), ML_DSA_87, POLICY));
    }

    /** Contract phase: "refuse non-hybrid" is just a smaller policy. */
    @Test
    void contractPhasePolicy_rejectsNonHybrid() throws Exception {
        MLDSAKey key = mldsa(ML_DSA_44);
        assertThrows(JwtUtilException.class, () -> SignatureVerifiers.forKey(
                key.toPublicJWK(), ML_DSA_44, Set.of(ML_DSA_65_ES256)));
    }

    @Test
    void headerAlgDifferentFromKeyAlg_rejected() throws Exception {
        MLDSAKey key = mldsa(ML_DSA_44);
        assertThrows(JwtUtilException.class,
                () -> SignatureVerifiers.forKey(key.toPublicJWK(), ML_DSA_65_ES256, POLICY));
    }

    /** Even a (mis)configured policy allowing ES256 can't open the classical path. */
    @Test
    void classicalKey_rejectedEvenIfPolicyAllowsIt() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        assertThrows(JwtUtilException.class, () -> SignatureVerifiers.forKey(
                key.toPublicJWK(), JWSAlgorithm.ES256, Set.of(JWSAlgorithm.ES256)));
    }

    @Test
    void missingArguments_rejected() throws Exception {
        MLDSAKey key = mldsa(ML_DSA_44);
        assertThrows(JwtUtilException.class, () -> SignatureVerifiers.forKey(null, ML_DSA_44, POLICY));
        assertThrows(JwtUtilException.class, () -> SignatureVerifiers.forKey(key, null, POLICY));
        assertThrows(JwtUtilException.class, () -> SignatureVerifiers.forKey(key, ML_DSA_44, null));
    }
}