# Giltzarrapo
Python file cypher using AES and RSA.

### RSA key pair generation
A new RSA key pair can be generated using the following
```python
from giltzarrapo import Giltzarrapo
Giltzarrapo.generateRSApair()     #Generate keys at the current path, with name giltza_rsa & giltza_rsa.pub, without passphrase and with 4096 bits
Giltzarrapo.generateRSApair(
  dir = "/my/custom/path",        #Specify the path to save the keys
  name = "myKeyName",             #Specify the name of the keys. Pubkey is ends with .pub
  passphrase = "myPassphrase",    #Specify passphrase
  RSAlen = "RSAnumBits"           #Specify number of bits. Must be power of 2
)
```
&nbsp;  

### Encrypt simplest example
```python
from giltzarrapo import Giltzarrapo
Giltzarrapo().readPlain('file.txt').encrypt('AES passwd', 'RSA pubkey file').save('file.txt.enc')
```
The file 'file.txt' is encrypted using the password 'AES passwd' and the public key at 'RSA pubkey file'. The encrypted file is saved at 'file.txt.enc'
&nbsp;  
&nbsp;  

### Decrypt simplest example
```python
from giltzarrapo import Giltzarrapo
Giltzarrapo().readEncrypted('file.txt.enc').decrypt('AES passwd', 'RSA privkey file', 'privkey passphrase').save('file.txt.dec')
```
The file 'file.txt.enc' is decrypted with the password 'AES passwd' and the private key at 'RSA privkey file'. If the key was generated using a passphrase it must be specified at 'privkey passphrase', otherwise it is not required assuming a value of ''.  The decrypted file is saved at 'file.txt.dec'
&nbsp;  

##### Other options
There are other options that can be used. Also, the encryption/decryption can be performed step by step
```python
from giltzarrapo import Giltzarrapo
g = Giltzarrapo(chunkSize = 512)     #512 is the default size. Any power of 2 that satisfies "chunkSize * 8 <= RSAlen" can be used.

g.readPlain('file.txt')
g.encrypt('AES passwd', 'RSA pubkey file', 
  selected_block = 32,    #None by default. This option specifies the index of the block to encrypt with RSA. Any integer smaller than len(g.blocks) can be used
  fast = True,            #True by default. It can be disabled
  try_max = 10            #10 by default. This option specifies how many random blocks to check in order to select the one with the highest entropy
)
g.save('file.txt.enc', authfile = 'file.auth')    #Authfile can be used with fast at False allowing a fast decrypt if that file is provided

g.readEncrypted('file.txt.enc', authfile = 'file.auth')   #Authfile can be provided while reading the encrypted file
g.decrypt('AES passwd', 'RSA privkey file', 'privkey passphrase', selected_block = 32)    #None by default. Specifying the block makes the decryption faster, but it must be the block used during the encryption
g.save('file.txt.dec')
```
Check the encrypt and decrypt scripts for more detailed examples.  
Check -h option in those scripts for usage help and options
