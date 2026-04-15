package dev.ysdaeth.keystore;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

public class KeyRevitalizer {


    static SecretKey revitalizeKey(byte[] key, String algorithm) {
        Objects.requireNonNull(key, "Key bytes must not be null");
        return new SecretKeySpec(key, algorithm);
    }

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
