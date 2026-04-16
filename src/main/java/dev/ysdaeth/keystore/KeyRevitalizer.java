package dev.ysdaeth.keystore;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * Class recreates the keys based on the provided key and key algorithm name.
 */
public class KeyRevitalizer {


    /**
     * Creates a key from the encoded bytes and provided key algorithm name
     * @param key encoded key bytes {@link Key#getEncoded()}
     * @param algorithm key algorithm name {@link Key#getAlgorithm()}
     * @return symmetric key
     */
    static SecretKey revitalizeKey(byte[] key, String algorithm) {
        Objects.requireNonNull(key, "Key bytes must not be null");
        return new SecretKeySpec(key, algorithm);
    }

    /**
     * Creates key pair from the encoded bytes and provided key algorithm name.
     * @param privateKey private key bytes {@link PrivateKey#getEncoded()}
     * @param publicKey public key bytes {@link PublicKey#getEncoded()}
     * @param keyAlgorithm Key algorithm name {@link PrivateKey#getAlgorithm()}
     * @return key pair
     * @throws NoSuchAlgorithmException when security provider does not support the key algorithm
     * @throws InvalidKeySpecException when key is not designed to work with X509 or PKCS8 encoding.
     */
    static KeyPair revitalizeKeyPair(byte[] privateKey, byte[] publicKey, String keyAlgorithm)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        Objects.requireNonNull(privateKey,"Private key must not be null");
        Objects.requireNonNull(publicKey,"Public key must not be null");

        KeyFactory kf = KeyFactory.getInstance(keyAlgorithm);
        PrivateKey pv = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(publicKey));
        return new KeyPair(pub, pv);
    }

}
