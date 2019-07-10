Decrypt Ethereum Keyfile
========================

The sample keyfile is generated from a private key 1 encrypted with the password "a":

```bash
# cd into a temporary working directory
cd $(mkdir -d)

# Make a key
echo "0000000000000000000000000000000000000000000000000000000000000001" > plain_key.txt
geth --datadir . account import plain_key.txt
```
To run, pass in the path of the keyfile as the first argument to `main.py`. For example:

```bash
./main.py UTC--2019-07-10T14-02-05.192559973Z--7e5f4552091a69125d5dfcb7b8c2659029395bdf
```

You could repeat the process with a randomly generated 32 byte value represented as a hexadecimal string for test purposes:

* Generate a private key
* Repeat the steps above to create an encrypted keyfile
* Run `main.py` with the keyfile as input
* Enter password when prompted
* Output should be your original secret 

Dependencies
------------
Project developed on Ubuntu 18.04. On Ubuntu 16.04, `scrypt` module doesn't have the required OpenSSL version to carry out the necessary hashing. You could upgrade OpenSSL, or spin up a Ubuntu 18.04 VM.

The `sha3` module from [pysha3][1] is used for keccak hashing.

References
----------
* [Pysha3][1] - SHA-3 wrapper(keccak) for Python
* [Keccak code package][2]
* [Useful Stack Exchange answer][3]


[1]: https://pypi.org/project/pysha3/
[2]: https://github.com/XKCP/XKCP
[3]: https://ethereum.stackexchange.com/questions/3720/how-do-i-get-the-raw-private-key-from-my-mist-keystore-file
