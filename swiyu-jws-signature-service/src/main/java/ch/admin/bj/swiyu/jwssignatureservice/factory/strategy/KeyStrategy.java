package ch.admin.bj.swiyu.jwssignatureservice.factory.strategy;

import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import org.springframework.stereotype.Component;

/**
 * Key management strategy for MLDSAKey-based signing.
 * Parses a PEM-encoded ML-DSA private key and creates a signer.
 */
@Component("key")
public class KeyStrategy implements IKeyManagementStrategy {
    /**
     * Default constructor for KeyStrategy.
     * Required for frameworks and serialization.
     */
    public KeyStrategy() {
    }

    /**
     * Creates a signer from a PEM-encoded ML-DSA private key.
     *
     * @param signatureConfigurationDto the signature configuration
     * @return a JWSSigner instance
     * @throws KeyStrategyException if key parsing or signer creation fails
     */
    @Override
    public JWSSigner createSigner(SignatureConfigurationDto signatureConfigurationDto) throws KeyStrategyException {
        try {
            JWK jwk = JWK.parseFromPEMEncodedObjects(signatureConfigurationDto.getPrivateKey());
            if (jwk instanceof CompositeMLDSAKey composite) {
                return fromComposite(composite);   // PQEID: hybrid ML-DSA-65-ES256
            }
            return fromMLDSA(jwk.toMLDSAKey());
        } catch (JOSEException | RuntimeException e) {
            throw new KeyStrategyException(
                    "Failed to parse signing key (ML-DSA or composite) from PEM.", e);
        }
    }
}
