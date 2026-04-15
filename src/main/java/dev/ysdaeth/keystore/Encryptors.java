package dev.ysdaeth.keystore;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.CryptographicRegistry;
import dev.ysdaeth.autocrypt.encryption.EncryptionManager;
import dev.ysdaeth.autocrypt.encryption.Encryptor;
import dev.ysdaeth.autocrypt.encryption.EncryptorAesGcm;

/**
 * Algorithm identifiers, basic spec resolvers and algorithm registry
 */
public class Encryptors {

    static final AlgorithmIdentifier IDENTIFIER_AES_GCM = new AlgorithmIdentifier((byte) 0x01, (byte) 0x06);
    private static final CryptographicRegistry<Encryptor> registry;

    static{
        registry = CryptographicRegistry.of(
          new EncryptorAesGcm(IDENTIFIER_AES_GCM)
        );
    }

    static EncryptionManager createEncryptionManager(){
        return new EncryptionManager(registry);
    }

    public static String resolveKeyAlgorithmName(AlgorithmIdentifier identifier) throws AlgorithmIdentificationException {
        if(IDENTIFIER_AES_GCM.equals(identifier)) return "AES";
        throw new AlgorithmIdentificationException("Cannot resolve key algorithm from unknown identifier: "+identifier);
    }

    public static int resolveKeyLength(AlgorithmIdentifier identifier) throws AlgorithmIdentificationException {
        if(IDENTIFIER_AES_GCM.equals(identifier)) return 256;
        throw new AlgorithmIdentificationException("Cannot resolve key algorithm from unknown identifier: "+identifier);
    }
}
