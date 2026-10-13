package ch.admin.bj.swiyu.jwssignatureservice.factory.strategy;

import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.CompositeSigner;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.StringWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** PQEID: KeyStrategy picks the signer from the PEM key type. */
class KeyStrategyTest {

    private final KeyStrategy strategy = new KeyStrategy();

    @BeforeAll
    static void registerBc() {
        // BC's composite generator looks up its components by provider name "BC"
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
    }

    private static String pem(String jcaAlg, boolean withPublic) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance(jcaAlg, "BC");
        if ("EC".equals(jcaAlg)) g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();        StringWriter sw = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(sw)) {
            w.writeObject(kp.getPrivate());
            if (withPublic) w.writeObject(kp.getPublic());
        }
        return sw.toString();
    }

    private JWSSigner signerFor(String pem) throws KeyStrategyException {
        return strategy.createSigner(SignatureConfigurationDto.builder()
                .keyManagementMethod("key").privateKey(pem).build());
    }

    @Test
    void compositePem_givesCompositeSigner() throws Exception {
        JWSSigner signer = signerFor(pem("MLDSA65-ECDSA-P256-SHA512", true));
        assertThat(signer).isInstanceOf(CompositeSigner.class);
        assertThat(signer.supportedJWSAlgorithms()).containsExactly(JWSAlgorithm.ML_DSA_65_ES256);
    }

    @Test
    void mldsaPem_stillGivesMldsaSigner() throws Exception {
        // regression: today's ML-DSA-44 .env keys (private block only) keep working
        assertThat(signerFor(pem("ML-DSA-44", false))).isInstanceOf(MLDSASigner.class);
    }

    @Test
    void ecPem_rejectedWithKeyStrategyException() {
        assertThatThrownBy(() -> signerFor(pem("EC", false)))
                .isInstanceOf(KeyStrategyException.class);
    }
}