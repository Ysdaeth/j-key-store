package dev.ysdaeth.keystore;

import jdk.jshell.spi.ExecutionControl;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;

import java.util.HexFormat;
import java.util.Optional;

public class KeyStore {
    private static final String KEY_FILE_EXTENSION = ".entry";

    private final Path keyStorePath;

    public KeyStore(Path keyStorePath, String keyStoreName) throws IOException {
        this.keyStorePath = Path.of(keyStorePath.toString(), keyStoreName);
        Files.createDirectories(this.keyStorePath);
    }


    public void store(String alias, SecretKey key, char[] password) throws IORuntimeException {
        // to key entry
        // secure key entry
        // store key entry
        throw new RuntimeException("store secret key method not implemented");
    }

    public void store(String alias, KeyPair keys, char[] password) throws IORuntimeException {
        // to key entry
        // secure key entry
        // store secure key entry
        throw new RuntimeException("store key pair method not implemented");
    }

    public Optional<SecretKey> getKey(String alias, char[] password)
            throws IORuntimeException, IllegalArgumentException {
        // load secure entry
        // decrypt secure key entry
        // key entry to key
        throw new RuntimeException("get secret key method not implemented");

    }

    public Optional<KeyPair> getKeyPair(String alias, char[] password)
            throws UnrecoverableEntryException {
        throw new RuntimeException("get key pair method not implemented");
    }


    private static String createFilename(String alias){
        byte[] byteAlias = alias.getBytes(StandardCharsets.UTF_8);
        byte[] hash;

        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(byteAlias);
        }catch (Exception e){
            throw new RuntimeException("Failed to create filename. "+e.getMessage(),e);
        }

        HexFormat format = HexFormat.of();
        return format.formatHex(hash) + KEY_FILE_EXTENSION;
    }
}
