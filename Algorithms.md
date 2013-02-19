## Supported Cryptographic Algorithms

#### Default Algorithms:

 - HMAC SHA1 (Symmetric - Sign and Verify)
 - AES-CBC 128 + HMAC 256 SHA1(Symmetric - Encrypt and Decrypt)
 - DSA 1048 SHA1 (Asymmetric - Sign and Verify)
 - RSA-OAEP 2048 SHA1 (Asymmetric - Encrypt and Decrypt)

#### Unofficial Default Algorithms:

 - AES-GCM 256 (Symmetric - Encrypt and Decrypt)
 - RSA-PSS 2048 SHA224 (Asymmetric - Sign and Verify)

#### Encryption:
 - Symmetric
  - AES-CBC 128 + HMAC 256 SHA1
  - AES-CBC 192 + HMAC 256 SHA1
  - AES-CBC 256 + HMAC 256 SHA1
  - AES-GCM 256 w/ 128 bit MAC
  - AES-GCM 192 w/ 128 bit MAC
  - AES-GCM 128 w/ 128 bit MAC
 - Asymmetric
   - RSA-OAEP 1024
   - RSA-OAEP 2048
   - RSA-OAEP 4096

#### Digital signature:
 - Asymmetric
   - DSA 1024 SHA1
   - RSA-PKCS 1024 SHA1
   - RSA-PKCS 2048 SHA1
   - RSA-PKCS 4096 SHA1
   - RSA-PSS 1024 SHA1
   - RSA-PSS 2048 SHA224
   - RSA-PSS 3078 SHA256
   - RSA-PSS 4096 SHA256

#### Message Authentication
 - Symmetric
   - HMAC 256 SHA1
