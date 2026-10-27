# Simpler Key store
, `Different passwords`, `One key, one file`

**Simple API**  
Designed to store the keys in a secure and easy way, when all that you think about is 
to store the key and get the key.  

**Different passwords**   
Each stored key can be protected with different password.  

**One key, one file**   
Directory with the keys, rather than all keys in a single file. It makes integrations easier with the 
key access loggers, intrusion detection systems, decoy files, etc.

> [!WARNING]
> Supported key pairs encodings are X509 for public and PKCS8 for private keys.
---

### [How to install](docs/Installation.md) 
### [How to use](docs/HowToUse.md)

---

## Requirements
- Java 25
- Designed for the OpenJDK