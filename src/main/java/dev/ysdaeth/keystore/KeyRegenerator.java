package dev.ysdaeth.keystore;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class KeyRegenerator {

    static SecretKey toSecretKey(KeyEntry entry) {
        if(entry.isDestroyed()) throw new IllegalStateException("Entry is destroyed");
        if(entry.publicKey() != null){
            throw new IllegalArgumentException("Key is not symmetric instance");
        }
        return new SecretKeySpec(entry.key(), entry.algorithm());
    }

    static KeyPair toKeyPair(KeyEntry entry)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        if(entry.isDestroyed()) throw new IllegalStateException("Entry is destroyed");
        if(entry.publicKey() == null){
            throw new IllegalArgumentException("Key is not asymmetric instance");
        }
        KeyFactory kf = KeyFactory.getInstance(entry.algorithm());
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(entry.key()));
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(entry.publicKey()));

        return new KeyPair(publicKey, privateKey);
    }

}
