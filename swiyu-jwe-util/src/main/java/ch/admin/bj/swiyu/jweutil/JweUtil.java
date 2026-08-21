package ch.admin.bj.swiyu.jweutil;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.XWingDecrypter;
import com.nimbusds.jose.crypto.XWingEncrypter;
import com.nimbusds.jose.crypto.opts.MaxCompressedCipherTextLength;
import com.nimbusds.jose.jwk.XWingKey;
import com.nimbusds.jose.jwk.JWK;
import lombok.experimental.UtilityClass;

import java.util.HashSet;
import java.util.Set;

/**
 * Service for JSON Web Encryption (JWE) operations in the Swiyu ecosystem.
 * <p>
 * This class provides a placeholder for future JWE encryption and decryption functionality.
 * It is intended to offer methods for encrypting and decrypting payloads using JWE standards.
 * </p>
 * <p>
 * Note: This is a stub and does not contain any real implementation yet.
 * </p>
 */
@UtilityClass
public class JweUtil {

    /**
     * Encrypts the given payload using JWE.
     *
     * @param payload The data to encrypt (as a String).
     * @return The encrypted JWE string, or null if not implemented.
     */
    // PQEID: ECDH-ES -> XWING (post-quantum hybrid KEM, X25519+ML-KEM-768). ML-DSA
    // (signature) could not replace ECDH-ES (key agreement) - see git history for that
    // category error. The actual PQC replacement for a key-AGREEMENT scheme is a KEM;
    // XWingKey/XWingEncrypter/XWingDecrypter were added to repos/nimbus-jose-jwt for
    // this purpose (not a standardized JOSE algorithm - project-specific "XWING" alg,
    // see JWEAlgorithm.XWING javadoc).
    public static String encrypt(String payload, JWK recipientPublicKey) {
        try {
            if (!(recipientPublicKey instanceof XWingKey xwKey)) {
                throw new JweUtilException("Only X-Wing keys are supported.");
            }
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.XWING, EncryptionMethod.A128GCM)
                    .compressionAlgorithm(CompressionAlgorithm.DEF)
                    .keyID(xwKey.getKeyID())
                    .build();
            JWEObject jweObject = new JWEObject(header, new Payload(payload));
            jweObject.encrypt(new XWingEncrypter(xwKey));
            return jweObject.serialize();
        } catch (Exception e) {
            throw new JweUtilException("Error during JWE encryption", e);
        }
    }

    /**
     * Decrypts the given JWE string.
     *
     * @param jweString           JWE as a String
     * @param recipientPrivateKey Empfänger-Privater Schlüssel (MLDSAKey)
     * @return plaintext payload
     */
    public static String decrypt(String jweString, JWK recipientPrivateKey) {
        return decrypt(jweString, recipientPrivateKey, null);
    }

    /**
     * Decrypts the given JWE string.
     *
     * @param jweString           JWE as a String
     * @param recipientPrivateKey private key (MLDSAKey) of the recipient
     * @param maxCompressedCipherTextLength Maximum length for compressed ciphertexts Default value (if null or 0) is 100000
     * @return plaintext payload
     */
    public static String decrypt(String jweString, JWK recipientPrivateKey, Integer maxCompressedCipherTextLength) {

        Set<JWEDecrypterOption> jweDecrypterOptions = new HashSet<>();

        if (maxCompressedCipherTextLength != null && maxCompressedCipherTextLength > 0) {
            jweDecrypterOptions.add(new MaxCompressedCipherTextLength(maxCompressedCipherTextLength));
        }

        // PQEID: ECDH-ES -> XWING, see encrypt() above.
        try {
            if (!(recipientPrivateKey instanceof XWingKey xwKey)) {
                throw new JweUtilException("Only X-Wing keys are supported.");
            }
            JWEObject jweObject = JWEObject.parse(jweString);
            jweObject.decrypt(new XWingDecrypter(xwKey), jweDecrypterOptions);
            return jweObject.getPayload().toString();
        } catch (Exception e) {
            throw new JweUtilException("Error during JWE decryption", e);
        }
    }
}
