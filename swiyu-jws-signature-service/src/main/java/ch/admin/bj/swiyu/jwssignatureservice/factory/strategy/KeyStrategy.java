package ch.admin.bj.swiyu.jwssignatureservice.factory.strategy;

import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
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
            return fromMLDSA(JWK.parseFromPEMEncodedObjects(signatureConfigurationDto.getPrivateKey()).toMLDSAKey());
        } catch (JOSEException e) {
            throw new KeyStrategyException("Failed to parse ML-DSA Key from PEM.", e);
        }
    }
}
