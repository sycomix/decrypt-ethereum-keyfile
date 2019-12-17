# Decrypt Ethereum Keyfile
Decrypt an Ethereum keyfile to recover the original private key.

Usage
-----
* Install dependencies listed in `requirements.txt`.
* Run `./main.py` with a path to an Ethereum keyfile as the first command-line argument.
* Enter your password when prompted.
* If the password is correct, the private key will be output to stdout.

__Be careful with your private keys__. If you use this repo to decrypt your private key from an Ethereum keyfile and a malicious person gets hold of it, they gain control over all funds held by that private key.

In my case, I wanted to ensure that I could access my private keys without necessarily relying on `geth` - so this repo is something of an academic exercise.

If you want to make a backup of Ethereum keys, just backup the keyfiles - the private key is encrypted already, and any Ethereum client should be able to use the keyfile format. This assumes of course that you have used a strong passphrase to secure your keys. 

Introduction
------------
Ethereum keyfiles include a password encrypted private key along with additional metadata relating to the encryption scheme. Keyfiles are stored by default in a `keystore` directory.

Keyfiles are in JSON format.

[Go Ethereum][5] is the official Golang implementation of the Ethereum protocol. It's CLI client, `geth`, does not allow private keys to be exported in plaintext. This is in contrast to Bitcoin Core where the `dumpprivkey` command provides access to decrypted private keys.

The purpose of this project is to decrypt the Ethereum private key from the keyfile when the password is known.

Example Ethereum Keyfile
------------------------
The sample keyfile shown below is generated from a private key `82633960e2a725ab641067a12b05fcaeca860d45ba785f634318490261e5d1a1` - 32 pseudo-random bytes - encrypted with the password "password123":

```json
{
  "address": "15d5d89632dc2d185aa27907ad42b1012ef1c982",
  "crypto": {
    "cipher": "aes-128-ctr",
    "ciphertext": "050d93d6a4e396a0cb74d021d0de9b1ed7860c0fd843b28acefbd3dc61314a19",
    "cipherparams": {
      "iv": "6aa1de28f8f43a522e6ac987c18bf66e"
    },
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "n": 262144,
      "p": 1,
      "r": 8,
      "salt": "b04dcccf351dba67460e5bf322493ab25b4e1b314df970503ed43c392166d4c8"
    },
    "mac": "c9a7a0c880289d267c49bf828ace98ecb89c64d600bbeed718dac9f605083e61"
  },
  "id": "62b2bcce-9ba7-49a4-8f67-59fb366ac7dd",
  "version": 3
}

```
Encryption Scheme
-----------------
The keyfile holds the encrypted private key in the `crypto.ciphertext` field.

The encryption scheme is an AES-128-CTR cipher, using scrypt as a key derivation function (to derive a block cipher key from a text-based password) and message authentication code (MAC) to authenticate the password.

The private key is symmetrically encrypted using AES-128 with block cipher mode CTR. In this case, the [scrypt][6] key derivation function is used to generate an AES symmetric key from the original password. An initialization vector is also required for decryption - and this is held in the `crypto.cipherparams.iv` field.

Relevant fields are:

* `crypto.cipher`: Denotes the cryptographic block-cipher algorithm, key size in bits and block cipher mode of operation.
* `crypto.ciphertext`: The encrypted private key.
* `crypto.cipherparams.iv`: The initialization vector required for AES in counter (CTR) mode.
* `crypto.kdf`: Denotes the key derivation function used - in this case, `srypt`.
* `crypto.kdfparams`: These variables are used in the kdf function - see [decrypt_key.py][8], [scrypt wikipedia][6]
* `crypto.mac`: Message authentication code - used to check the authenticity of the key derived from the user-supplied password.

Key Derivation
--------------
Requires the user-supplied password and the `crypto.kdfparams`.

Uses the `hashlib.scrypt` function. See note below re: Ubuntu 16.04 vs Ubuntu 18.04.

From [derive_key.py][8]: 
```py
import hashlib

def key(password, data):
    key = hashlib.scrypt(
        bytes(password, 'utf-8'),
        salt=bytes.fromhex(data["kdfparams"]["salt"]),
        n=data["kdfparams"]["n"],
        r=data["kdfparams"]["r"],
        p=data["kdfparams"]["p"],
        maxmem=2000000000,
        dklen=data["kdfparams"]["dklen"]
        )
    return key  
```

Message Authentication
----------------------
Once the decryption key is derived from the password, it is authenticated by:

* Removing the first 16 bytes from the derived key.
* Concatenating this value (key excluding first 16 bytes) with the ciphertext bytes.
* Comparing the keccak hash of this value with the value of the `crypto.mac` field.
* If these values are the same, the key is authentic.

From [password_verify.py][7]:

```py
import sha3

def verify(key, data):
    validate = key[16:] + bytes.fromhex(data["ciphertext"])
    keccak_hash = sha3.keccak_256()
    keccak_hash.update(validate)
    if data["mac"] == keccak_hash.hexdigest():
        return True
    else:
        return False
```
Decryption
----------
Once the encryption key has been derived from the user-supplied password and the KDF parameters, it can be used to decrypt `crypto.cipertext` - yielding the decrypted private key. 

This project uses the AES function from the [Crypto.Cipher][9] package. 

Generate a Private Key and Keyfile for Testing
----------------------------------------------

* Generate a private key
* Create an encrypted Ethereum keyfile
* Run `main.py` with the newly generated keyfile as input
* Enter password when prompted 
* Output should be the original private key 

```bash
# cd into a temporary working directory
cd $(mktemp -d)

# Make a private key from 32 pseudo-random bytes
head -c 32 /dev/random | xxd -ps -c 32 > plain_key.txt

# Make an Ethereum key file - assumes geth is installed, prompts for password
geth --datadir . account import plain_key.txt
```
Pass in the path of the keyfile as the first argument to `main.py`. For example:

```bash
./main.py UTC--2019-07-10T14-02-05.192559973Z--7e5f4552091a69125d5dfcb7b8c2659029395bdf
```

You'll be prompted for the password and the original private key will be output.

Dependencies
------------
Project developed on Ubuntu 18.04. On Ubuntu 16.04, `scrypt` module doesn't have the required OpenSSL version to carry out the necessary hashing. You could upgrade OpenSSL, or spin up a Ubuntu 18.04 VM.

The `sha3` module from [pysha3][1] is used for keccak hashing.

References
----------
* [Pysha3][1] - SHA-3 wrapper(keccak) for Python
* [Keccak code package][2]
* [Useful Stack Exchange answer][3]
* [Bitcoin Core dumpprivkey command][4]
* [Go Ethereum][5], GitHub repo
* [scrypt key derivation function][6]


[1]: https://pypi.org/project/pysha3/
[2]: https://github.com/XKCP/XKCP
[3]: https://ethereum.stackexchange.com/questions/3720/how-do-i-get-the-raw-private-key-from-my-mist-keystore-file
[4]: https://bitcoin.org/en/developer-reference#dumpprivkey
[5]: https://github.com/ethereum/go-ethereum
[6]: https://en.wikipedia.org/wiki/Scrypt
[7]: /password_verify.py
[8]: /derive_key.py
[9]: https://pycryptodome.readthedocs.io/en/latest/src/cipher/cipher.html
