package dev.ysdaeth.keystore;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.CryptographicRegistry;
import dev.ysdaeth.autocrypt.encryption.EncryptionManager;
import dev.ysdaeth.autocrypt.encryption.Encryptor;
import dev.ysdaeth.autocrypt.encryption.EncryptorAesGcm;

/**
 * Algorithm identifiers, basic key spec resolvers and algorithm registry.
 * Supported Encryption algorithms are
 * <ul>
 *     <li>AES GCM</li>
 * </ul>
 */
public class Encryptors {

    static final AlgorithmIdentifier IDENTIFIER_AES_GCM = new AlgorithmIdentifier((byte) 0x01, (byte) 0x06);

    /**
     * registry responsible for auto encryption and decryption cryptographic instances
     */
    private static final CryptographicRegistry<Encryptor> registry;


    // Init static registry of encryptors
    static{
        registry = CryptographicRegistry.of(
          new EncryptorAesGcm(IDENTIFIER_AES_GCM)
        );
    }

    /**
     * Returns new encryption manager for decryption algorithm resolving, and providing ready implementations
     * @return encryption manager
     */
    static EncryptionManager createEncryptionManager(){
        return new EncryptionManager(registry);
    }

    /**
     * Returns name of the key algorithm based on the provided algorithm identifier.
     * @param identifier algorithm identifier
     * @return string key algorithm name that can be used with {@link javax.crypto.KeyGenerator} and other.
     * @throws AlgorithmIdentificationException when there is no algorithm that matches algorithm identifier.
     */
    public static String resolveKeyAlgorithm(AlgorithmIdentifier identifier) throws AlgorithmIdentificationException {
        if(IDENTIFIER_AES_GCM.equals(identifier)) return "AES";
        throw new AlgorithmIdentificationException("Cannot resolve key algorithm from unknown identifier: "+identifier);
    }

    /**
     * Resolves recommended key length for specified algorithm identifier.
     * @param identifier algorithm identifier
     * @return size in bits of the key length
     * @throws AlgorithmIdentificationException when there is no algorithm that matches the identifier
     */
    public static int resolveKeyLength(AlgorithmIdentifier identifier) throws AlgorithmIdentificationException {
        if(IDENTIFIER_AES_GCM.equals(identifier)) return 256;
        throw new AlgorithmIdentificationException("Cannot resolve key algorithm from unknown identifier: "+identifier);
    }
}
