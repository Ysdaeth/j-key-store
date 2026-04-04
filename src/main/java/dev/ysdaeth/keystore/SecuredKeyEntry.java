package dev.ysdaeth.keystore;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

record SecuredKeyEntry(String alias,
                       String keyAlg,
                       byte[] key,
                       byte[] pubKey,
                       String protectionType,
                       String protectionAlg,
                       Map<String,String> protectionParams) {

    SecuredKeyEntry(String alias,
                    String keyAlg,
                    byte[] key,
                    String protectionType,
                    String protectionAlg,
                    Map<String,String> protectionArgs) {
        this(alias, keyAlg, key, null, protectionType, protectionAlg, protectionArgs);
    }

    /**
     * Create secured key file entry from given arguments.
     * @param alias key alias
     * @param keyAlg key algorithm
     * @param key encrypted key bytes
     * @param protectionParams protection parameters like key derivation function, or salt, etc.
     */
    SecuredKeyEntry {
        Objects.requireNonNull(alias, "alias must not be null");
        Objects.requireNonNull(keyAlg, "Key algorithm must not be null");
        Objects.requireNonNull(key, "Key must not be null");
        Objects.requireNonNull(protectionType,"Protection type must not be null");
        Objects.requireNonNull(protectionAlg,"Protection algorithm must not be null");
    }

    static class Builder {
        private String alias = null;
        private String keyAlg = null;
        private byte[] key = null;
        private byte[] pubKey = null;
        String protectionType = null;
        String protectionAlg = null;
        private Map<String,String> protectionParams = new HashMap<>();

        Builder alias(String alias){
            this.alias = alias;
            return this;
        }

        Builder keyAlg(String keyAlg){
            this.keyAlg = keyAlg;
            return this;
        }

        Builder key(byte[] key){
            this.key = key;
            return this;
        }

        Builder pubKey(byte[] pubKey){
            this.pubKey = pubKey;
            return this;
        }
        Builder protectionType(String protectionType){
            this.protectionType = protectionType;
            return this;
        }
        Builder protectionAlg(String protectionAlg){
            this.protectionAlg = protectionAlg;
            return this;
        }
        Builder addProtectionParam(Map.Entry<String,String> paramArg){
            this.protectionParams.put(paramArg.getKey(), paramArg.getValue() );
            return this;
        }
        SecuredKeyEntry build(){
            return new SecuredKeyEntry(alias, keyAlg, key, pubKey, protectionType, protectionAlg, protectionParams);
        }
    }
}
