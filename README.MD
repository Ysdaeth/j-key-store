# Key store for java
Library for storing the keys in the local storage in the easy and secure way.

## Simple API
API designed to store the keys in a secure and easy way, when all that you think about is 
to store the key, and get the key secured with password.

## Different passwords  
Unlike Java KeyStore, each key can have its own password.
Additionally, even when using the same password, a new encryption key is
generated each time, that means each encryption key is used only once, make it more secure.

## One key, one file 
Directory with the keys, rather than all keys in a single file. It makes integrations easier with the 
key access loggers, intrusion detection systems (decoy files), etc.

> [!WARNING]
> Supported key pairs encodings are X509 for public and PKCS8 for private keys.
> Depends on the Security Provider - designed for the OpenJDK

## How to use
> [!IMPORTANT]
> Repository depends on my [other repository](https://github.com/Ysdaeth/j-autocrypt). Maven and GitHub Packages are
> not available to download before Jun 2026. To install, clone repo and use "mvn clean install" 
### Add dependency
First lets add dependency
```xml
<dependency>
    <groupId>dev.ysdaeth.keystore</groupId>
    <artifactId>j-keystore</artifactId>
    <version>0.1</version>
</dependency>
```

---
### Create key store
Make sure that KeyStore is from the dev.ysdaeth.keystore package, since Java KeyStore has the same name.  
Keystore will create a directory in the specified `keyStorePath` with the specified `keyStoreName`. In the
directory `keyStoreName` will be placed all encrypted keys.
```java
KeyStore keyStore = new KeyStore(keyStorePath, keyStoreName);
```

---

### Store the key
First, we will generate a key to store in the key sore. KeyPair works the same way, but in case of the key pair,
a public key is not encrypted. Then, we'll store generated key secured with password. One password generates
different encryption keys to make it more secure when key store files leak. Leaking password does not prevent it, 
remember that you can use different password for each entry.
```java
SecretKey keyToStore = KeyGenerator.getInstance("AES").generateKey(); //generate a key to store
String keyAlias = "key-to-store"; // create alias for key to store
char[] password = "password".toCharArray(); // create password to secure key

keyStore.store(keyAlias, keyToStore, password);
```

---

### Get stored key
When we have already stored out key, we can load it from the key store. Method returns optional.
```java
Optional<SecretKey> optionalKey = keyStore.getKey(alias, password);
```

## Requirements
- Java 25
- Designed for the OpenJDK

## TODO
- [ ] Better support for asymmetric keys