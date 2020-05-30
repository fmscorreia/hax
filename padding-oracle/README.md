# Padding Oracle Attack script

Notes:

* HTTP requests are limited to one parameter (the ciphertext).
* Expects a transformed base64 ciphertext as input. Check functions `transform` and `reverse` in the source code, change these as required.

## Usage

```
$ ./padding-oracle.py -h
usage: padding-oracle-encrypt.py [-h] [-p PLAINTEXT] [-D] {GET,POST} url block_size ciphertext_param

##### Padding Oracle Attack script #####

positional arguments:
  {GET,POST}            HTTP request method
  url                   Target URL
  block_size            Cipher block size
  ciphertext_param      Request parameter that takes the ciphertext value. Format: name=ciphertext

optional arguments:
  -h, --help            show this help message and exit
  -p PLAINTEXT, --plaintext PLAINTEXT
                        Plaintext to encrypt. Setting the plaintext will enter "Encrypt" mode
  -D, --debug           Debug mode
```

## Sources

[Padding Oracle Attack explanation](https://robertheaton.com/2013/07/29/padding-oracle-attack/)

[Encrypting arbitrary plaintext](https://crypto.stackexchange.com/questions/29706/creating-own-ciphertext-after-a-padding-oracle-attack/50050#50050)
