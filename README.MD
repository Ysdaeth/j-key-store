# Key store for java
Library to store the keys in the local storage in the easy and secure way.

## Simple API
API designed to store the keys in a secure and easy way, when all that you think about is 
to store the key and get the key.

## Different passwords  
Each key have its own password. 
Additionally, using the same password generates a new encryption key everytime, that means each entry is 
encrypted with different encryption key.

## One key, one file 
Directory with the keys, rather than all keys in a single file. It makes integrations easier with the 
key access loggers, intrusion detection systems (decoy files), etc.

> [!WARNING]
> Supported key pairs encodings are X509 for public and PKCS8 for private keys.

## How to use
> [!IMPORTANT]
> Repository depends on my [other repository](https://github.com/Ysdaeth/j-autocrypt). Maven and GitHub packages
> will be available to download after Jun 2026. 
### Add dependency
First lets add the dependency
```xml
<dependency>
    <groupId>dev.ysdaeth.keystore</groupId>
    <artifactId>j-keystore</artifactId>
    <version>0.1</version>
</dependency>
```

---
### Create key store
Make sure that KeyStore is from the `dev.ysdaeth.keystore package`, Java KeyStore has the same name.  
Keystore will create a directory in the specified `keyStorePath` and name of that directory will be `keyStoreName`. 
In the directory `keyStoreName` will be placed files that contain metadata and encrypted keys.
```java
KeyStore keyStore = new KeyStore(keyStorePath, keyStoreName);
```

---

### Store the key
First, we will generate a key to store it in the KeyStore. Storing the key pairs works the same way, but
a public key is not encrypted. Now, we'll store generated key secured with password. One password generates
different encryption keys to give more time to rotate the keys, if key store is leaked.
```java
SecretKey keyToStore = KeyGenerator.getInstance("AES").generateKey(); //generate a key to store
String keyAlias = "key-to-store"; // create alias for key to store
char[] password = "password".toCharArray(); // create password to secure key

keyStore.store(keyAlias, keyToStore, password);
```

> [!TIP] You use different passwords for each entry
---

### Get stored key
When we have already stored our key, we can load it from the key store. Method returns optional.
```java
Optional<SecretKey> optionalKey = keyStore.getKey(alias, password);
```

## Requirements
- Java 25
- Designed for the OpenJDK

## TODO
- [ ] Better support for asymmetric keys