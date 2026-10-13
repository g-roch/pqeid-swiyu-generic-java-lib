package ch.admin.bj.swiyu.jwtutil;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.CompositeSigner;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Set;

import static com.nimbusds.jose.JWSAlgorithm.ML_DSA_44;
import static com.nimbusds.jose.JWSAlgorithm.ML_DSA_65_ES256;
import static org.junit.jupiter.api.Assertions.*;

/** PQEID: JwtUtil verification goes through the algorithm policy. */
class JwtUtilPolicyTest {

    @BeforeAll
    static void registerBc() {
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
    }

    private static SignedJWT jwt(String kid, com.nimbusds.jose.JWSAlgorithm alg) {
        return new SignedJWT(new JWSHeader.Builder(alg).keyID(kid).build(),
                new JWTClaimsSet.Builder().subject("s").build());
    }

    @Test
    void compositeJwt_verifiesThroughJwkSet() throws Exception {
        // Arrange
        KeyPair kp = KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC")
                .generateKeyPair();
        CompositeMLDSAKey key = CompositeMLDSAKey.fromJCA(kp.getPublic(), kp.getPrivate(), "k1");
        SignedJWT signed = jwt("k1", ML_DSA_65_ES256);
        signed.sign(new CompositeSigner(key));
        // Act
        var claims = JwtUtil.verifySignedJwt(signed, new JWKSet(key.toPublicJWK()));
         // Assert
        assertEquals("s", claims.get("sub"));
    }

    @Test
    void mldsa44Jwt_stillVerifiesWithDefaultPolicy() throws Exception {
        MLDSAKey key = new MLDSAKeyGenerator(ML_DSA_44).keyID("k2").generate();
        SignedJWT signed = jwt("k2", ML_DSA_44);
        signed.sign(new MLDSASigner(key));

        assertEquals("s", JwtUtil.verifySignedJwt(signed, new JWKSet(key.toPublicJWK())).get("sub"));
    }

    @Test
    void contractPolicy_rejectsMldsa44() throws Exception {
        MLDSAKey key = new MLDSAKeyGenerator(ML_DSA_44).keyID("k3").generate();
        SignedJWT signed = jwt("k3", ML_DSA_44);
        signed.sign(new MLDSASigner(key));

        assertThrows(JwtUtilException.class, () -> JwtUtil.verifySignedJwt(
                signed, new JWKSet(key.toPublicJWK()), Set.of(ML_DSA_65_ES256)));
    }


}