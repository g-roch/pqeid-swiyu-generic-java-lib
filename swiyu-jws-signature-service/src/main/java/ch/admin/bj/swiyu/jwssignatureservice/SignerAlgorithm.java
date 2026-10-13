package ch.admin.bj.swiyu.jwssignatureservice;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.CompositeSigner;
import com.nimbusds.jose.crypto.MLDSASigner;

import java.util.Set;

/**
 * PQEID crypto agility: the JWS header "alg" comes from the configured key (via its signer),
 * never from a constant. Changing the key in .env changes the algorithm, no code change.
 * Which algorithms are ACCEPTED when verifying is a separate policy (allow-list).
 */
public final class SignerAlgorithm {

    private SignerAlgorithm() {
    }

    /**
     * @param signer a signer created from the configured key
     * @return the JWS algorithm of that key
     * @throws IllegalArgumentException if it can't be determined unambiguously
     */
        public static JWSAlgorithm of(JWSSigner signer) {
        if (signer instanceof MLDSASigner s) {
            return jws(s.getPrivateKey().getAlgorithm(), signer);
        }
        if (signer instanceof CompositeSigner s) {
            return jws(s.getPrivateKey().getAlgorithm(), signer);
        }
        if (signer != null) {
            // e.g. ECDSASigner: one algorithm per key curve
            Set<JWSAlgorithm> algs = signer.supportedJWSAlgorithms();
            if (algs.size() == 1) {
                return algs.iterator().next();
            }
        }
        throw new IllegalArgumentException("Cannot determine a single JWS algorithm for " + signer);
    }

    private static JWSAlgorithm jws(Algorithm alg, JWSSigner signer) {
        if (alg instanceof JWSAlgorithm jwsAlg) {
            return jwsAlg;
        }
        throw new IllegalArgumentException("Signing key has no JWS algorithm: " + signer);
    }
}