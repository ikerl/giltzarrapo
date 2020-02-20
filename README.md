# Giltzarrapo
Python file cypher using AES and RSA.

#### Encrypt simplest example
```python
from giltzarrapo import Giltzarrapo
Giltzarrapo().readPlain('file.txt').encrypt('AES passwd', 'RSA pubkey file').save('file.txt.enc')
```
The file 'file.txt' is encrypted using the password 'AES passwd' and the public key at 'RSA public key file'. The encrypted file is saved at 'file.txt.enc'
&nbsp;  
&nbsp;  

#### Decrypt simplest example
```python
from giltzarrapo import Giltzarrapo
Giltzarrapo().readEncrypted('file.txt.enc').decrypt('AES passwd', 'RSA privkey file', 'privkey passphrase').save('file.txt.dec')
```
The file 'file.txt.enc' is decrypted with the password 'AES passwd' and the private key at 'RSA privkey file'. The decrypted file is saved at 'file.txt.dec'
&nbsp;  
&nbsp;  

###### RSA key pair generation
A new RSA key pair can be generated using the following
```python
from giltzarrapo import Giltzarrapo
Giltzarrapo.generateRSApair()           #Keys are generated at the default path
```
