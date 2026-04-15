package dev.ysdaeth.keystore;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

record SecuredKeyEntry(String alias,
                       String keyAlg,
                       byte[] key,
                       byte[] pubKey,
                       String kdfAlg,
                       Map<String,String> kdfParams
) {

    SecuredKeyEntry(String alias,
                    String keyAlg,
                    byte[] key,
                    String kdfAlg,
                    Map<String,String> kdfParams) {
        this(alias, keyAlg, key, null, kdfAlg, kdfParams);
    }

    /**
     * Create secured key file entry from given arguments.
     * @param alias key alias
     * @param keyAlg key algorithm
     * @param key encrypted key bytes
     * @param kdfParams protection parameters like key derivation function, or salt, etc.
     */
    SecuredKeyEntry {
        Objects.requireNonNull(alias, "alias must not be null");
        Objects.requireNonNull(keyAlg, "Key algorithm must not be null");
        Objects.requireNonNull(key, "Key must not be null");
        Objects.requireNonNull(kdfAlg,"Protection algorithm must not be null");
    }

    static Builder builder(){
        return new Builder();
    }

    static class Builder {
        private String alias;
        private String keyAlg;
        private byte[] key;
        private byte[] pubKey;
        private String kdfAlg;
        private Map<String,String> kdfParams = new HashMap<>();

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
        Builder derivationAlg(String protectionType){
            this.kdfAlg = protectionType;
            return this;
        }
        Builder kdfParams(Map<String,String> params){
            this.kdfParams = params;
            return this;
        }
        Builder addKdfParam(Map.Entry<String,String> entry){
            this.kdfParams.put(entry.getKey(), entry.getValue());
            return this;
        }
        SecuredKeyEntry build(){
            return new SecuredKeyEntry(alias, keyAlg, key, pubKey, kdfAlg, kdfParams);
        }
    }
}
