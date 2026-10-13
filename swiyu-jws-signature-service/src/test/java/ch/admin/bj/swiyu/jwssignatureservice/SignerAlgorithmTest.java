package ch.admin.bj.swiyu.jwssignatureservice;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.CompositeSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// PQEID: the header alg is the key's algorithm, and it is what the signer accepts.
class SignerAlgorithmTest {

    @BeforeAll
    static void registerBc() {
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
    }

    private static JWSSigner mldsa(JWSAlgorithm alg) throws Exception {
        return new MLDSASigner(new MLDSAKeyGenerator(alg).generate());
    }

    private static JWSSigner composite() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC")
                .generateKeyPair();
        return new CompositeSigner(CompositeMLDSAKey.fromJCA(kp.getPublic(), kp.getPrivate()));
    }

    // The derived alg must be accepted by the signer itself (no header/key mismatch). 
    private static void signsWithDerivedHeader(JWSSigner signer) throws Exception {
        JWSObject jws = new JWSObject(new JWSHeader(SignerAlgorithm.of(signer)), new Payload("x"));
        jws.sign(signer);
        assertThat(jws.getState()).isEqualTo(JWSObject.State.SIGNED);
    }

    @Test
    void mldsa44Key_givesMlDsa44() throws Exception {
        JWSSigner s = mldsa(JWSAlgorithm.ML_DSA_44);
        assertThat(SignerAlgorithm.of(s)).isEqualTo(JWSAlgorithm.ML_DSA_44);
        signsWithDerivedHeader(s);
    }

    @Test
    void mldsa65Key_givesMlDsa65_notTheFirstOfTheFamily() throws Exception {
        JWSSigner s = mldsa(JWSAlgorithm.ML_DSA_65);
        assertThat(SignerAlgorithm.of(s)).isEqualTo(JWSAlgorithm.ML_DSA_65);
        signsWithDerivedHeader(s);
    }

    @Test
    void compositeKey_givesMlDsa65Es256() throws Exception {
        JWSSigner s = composite();
        assertThat(SignerAlgorithm.of(s)).isEqualTo(JWSAlgorithm.ML_DSA_65_ES256);
        signsWithDerivedHeader(s);
    }

     @Test
    void ambiguousSigner_rejected() throws Exception {
        // a 64-byte secret allows HS256, HS384 and HS512: no single answer
        JWSSigner s = new MACSigner(new byte[64]);
        assertThatThrownBy(() -> SignerAlgorithm.of(s)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void nullSigner_rejected() {
        assertThatThrownBy(() -> SignerAlgorithm.of(null)).isInstanceOf(IllegalArgumentException.class);
    }
}


