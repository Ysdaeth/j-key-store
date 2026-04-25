# Simpler Key store

### Simple API
- API designed to store the keys in a secure and easy way, when all that you think about is 
to store the key and get the key.

### Different passwords  
- Each stored key can be protected with different password.

### One key, one file 
- Directory with the keys, rather than all keys in a single file. It makes integrations easier with the 
key access loggers, intrusion detection systems (decoy files), etc.

---

> [!WARNING]
> Supported key pairs encodings are X509 for public and PKCS8 for private keys.

> [!IMPORTANT]
> Repository depends on my [other repository](https://github.com/Ysdaeth/j-autocrypt). Maven and GitHub packages
> will be available to download after Jun 2026.

## How to use
 
### Add the dependency
First lets add the dependency
```xml
<dependency>
    <groupId>dev.ysdaeth.keystore</groupId>
    <artifactId>j-keystore</artifactId>
    <version>0.1</version>
</dependency>
```

---
### Create the key store
Make sure that KeyStore is from the `dev.ysdaeth.keystore package`, Java KeyStore has the same name.  
KeyStore will create a directory in the specified `keyStorePath` with `keyStoreName` name. 
In the directory `keyStoreName` will be placed encrypted keys.
```java
KeyStore keyStore = new KeyStore(keyStorePath, keyStoreName);
```

---

### Store the key
First we will generate a key to store it in the KeyStore. Storing the key pairs works the same way, but
a public key is not being encrypted. Now, we'll store the key and secure it with a password. Password generates each time 
different random encryption key to encrypt your key in the store.
```java
SecretKey keyToStore = KeyGenerator.getInstance("AES").generateKey(); //generate a key to store
String keyAlias = "key-to-store"; // create alias for key to store
char[] password = "password".toCharArray(); // create password to secure key

keyStore.store(keyAlias, keyToStore, password);
```

> [!TIP]
> Each entry is encrypted with a different random key to give you more time for the key rotation when key store leaks, 
> but leaking the keystore and password may be catastrophic. Remember that you can use 
> different passwords for each entry

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