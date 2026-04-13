package dev.ysdaeth.keystore;

import java.util.Map;
import java.util.Objects;

record SecuredKeyEntry(String alias,
                       String keyAlg,
                       byte[] key,
                       byte[] pubKey,
                       String derivationAlg,
                       Map<String,String> derivationParams
) {

    SecuredKeyEntry(String alias,
                    String keyAlg,
                    byte[] key,
                    String derivationAlg,
                    Map<String,String> derivationParams) {
        this(alias, keyAlg, key, null, derivationAlg, derivationParams);
    }

    /**
     * Create secured key file entry from given arguments.
     * @param alias key alias
     * @param keyAlg key algorithm
     * @param key encrypted key bytes
     * @param derivationParams protection parameters like key derivation function, or salt, etc.
     */
    SecuredKeyEntry {
        Objects.requireNonNull(alias, "alias must not be null");
        Objects.requireNonNull(keyAlg, "Key algorithm must not be null");
        Objects.requireNonNull(key, "Key must not be null");
        Objects.requireNonNull(derivationAlg,"Protection algorithm must not be null");
    }

    static Builder builder(){
        return new Builder();
    }

    static class Builder {
        private String alias;
        private String keyAlg;
        private byte[] key;
        private byte[] pubKey;
        private String derivationAlg;
        private Map<String,String> derivationParams;

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
            this.derivationAlg = protectionType;
            return this;
        }
        Builder derivationParams(Map<String,String> params){
            this.derivationParams = params;
            return this;
        }
        SecuredKeyEntry build(){
            return new SecuredKeyEntry(alias, keyAlg, key, pubKey, derivationAlg, derivationParams);
        }
    }
}
