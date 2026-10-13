package ch.admin.bj.swiyu.jwssignatureservice.factory.strategy;

import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.crypto.CompositeSigner;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;

import java.security.Provider;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;

/**
 * Interface for key management strategies used to create JWS signers.
 * Provides default methods for ML-DSA key-based signing with various providers.
 */
@FunctionalInterface
public interface IKeyManagementStrategy {
    /**
     * Creates a JWS signer based on the provided signature configuration.
     *
     * @param signatureConfigurationDto the signature configuration
     * @return a JWSSigner instance
     * @throws KeyStrategyException if signer creation fails
     */
    JWSSigner createSigner(SignatureConfigurationDto signatureConfigurationDto) throws KeyStrategyException;

    /**
     * Creates a signer from an MLDSAKey and a security provider.
     *
     * @param privateKey The private key loaded with MLDSAKey.load from the keystore
     * @param provider   Provider like Sun PKCS11 Provider, already used to initialize the keystore
     * @return a newly created Signing Support
     * @throws JOSEException if the Signer could not be created with the provided key &amp; provider
     */
    default JWSSigner fromMLDSA(MLDSAKey privateKey, Provider provider) throws JOSEException {
        var signer = new MLDSASigner(privateKey);
        signer.getJCAContext().setProvider(provider);
        return signer;
    }

    /**
     * PQEID: creates a signer from a composite (PQ/T hybrid) key, e.g. ML-DSA-65-ES256.
     *
     * @param privateKey composite key including the private part
     * @param provider   JCA provider implementing the LAMPS composites
     * @return a newly created Signing Support
     * @throws JOSEException if the Signer could not be created with the provided key
     */
    default JWSSigner fromComposite(CompositeMLDSAKey privateKey, Provider provider)
            throws JOSEException {
        var signer = new CompositeSigner(privateKey);
        signer.getJCAContext().setProvider(provider);
        return signer;
    }

    /** PQEID: as {@link #fromComposite(CompositeMLDSAKey, Provider)}, with BouncyCastle. */
    default JWSSigner fromComposite(CompositeMLDSAKey privateKey) throws JOSEException {
        return fromComposite(privateKey, BouncyCastleProviderSingleton.getInstance());
    }

    /**
     * Creates a signer from an MLDSAPrivateKey and a security provider (for HSM use).
     *
     * @param privateKey The private key loaded from the keystore. The keystore must have a certificate for it to work properly.
     * @param provider   Provider like Securosys Primus Provider, already used to initialize the keystore
     * @return a newly created Signing Support
     * @throws JOSEException if the Signer could not be created with the provided key &amp; provider
     */
    default JWSSigner fromMLDSA(MLDSAPrivateKey privateKey, Provider provider) throws JOSEException {
        var signer = new MLDSASigner(privateKey);
        signer.getJCAContext().setProvider(provider);
        return signer;
    }

    /**
     * Creates a signer from an MLDSAKey using the BouncyCastle provider.
     *
     * @param privateKey The private key loaded with MLDSAKey.load from a string using bouncycastle
     * @return a newly created Signing Support
     * @throws JOSEException if the Signer could not be created with the provided key &amp; provider
     */
    default JWSSigner fromMLDSA(MLDSAKey privateKey) throws JOSEException {
        return fromMLDSA(privateKey, BouncyCastleProviderSingleton.getInstance());
    }
}
