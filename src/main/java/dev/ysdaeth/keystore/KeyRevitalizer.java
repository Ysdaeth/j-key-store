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
final class KeyRevitalizer {


    /**
     * Creates a key from the encoded bytes and provided key algorithm name
     * @return symmetric key
     */
    static SecretKey revitalizeSymmetricKey(SecretKeyEntry secretKeyEntry) {
        return new SecretKeySpec(secretKeyEntry.keyBytes(), secretKeyEntry.algorithm());
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

        KeyFactory kf = KeyFactory.getInstance(keyAlgorithm);
        PrivateKey pv = revitalizePrivateKey(kf,privateKey);
        PublicKey pub = revitalizePublicKey(kf,publicKey);
        return new KeyPair(pub, pv);
    }

    static PublicKey revitalizePublicKey(PublicKeyEntry publicKeyEntry)
            throws NoSuchAlgorithmException, InvalidKeySpecException{

        KeyFactory kf = KeyFactory.getInstance(publicKeyEntry.algorithm());
        return revitalizePublicKey(kf, publicKeyEntry.keyBytes());
    }

    static PrivateKey revitalizePrivateKey(SecretKeyEntry secretKeyEntry)
            throws NoSuchAlgorithmException, InvalidKeySpecException{

        KeyFactory kf = KeyFactory.getInstance(secretKeyEntry.algorithm());
        return revitalizePrivateKey(kf,secretKeyEntry.keyBytes());
    }

    private static PublicKey revitalizePublicKey(KeyFactory keyFactory, byte[] publicKey)
            throws InvalidKeySpecException{

        if(publicKey == null) throw new IllegalArgumentException("Public key bytes must not be null");
        return keyFactory.generatePublic(new X509EncodedKeySpec(publicKey));
    }

    private static PrivateKey revitalizePrivateKey(KeyFactory keyFactory, byte[] privateKey)
            throws InvalidKeySpecException{

        if(privateKey == null) throw new IllegalArgumentException("Private key bytes must not be null");

        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
    }

}
