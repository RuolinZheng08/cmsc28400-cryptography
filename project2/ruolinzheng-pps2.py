#!/usr/bin/env python3

import urllib.request
from Crypto.Cipher import AES
import binascii
import base64
import random
import os
import zlib

from collections import Counter
import math
import argparse

VERBOSE = False
PPS2SERVER = "http://cryptoclass.cs.uchicago.edu/"

################################################################################
# CS 284 Padding Utility Functions
################################################################################

# s is a bytearray to pad, k is blocklength
# you won't need to change the block length
def cmsc284pad(s,k=16):
  if k > 255:
    print("pkcs7pad: padding block length must be less than 256")
    return bytearray()
  n = k - (len(s) % k)
  if n == 0:
    n = k
  for i in range(1,n+1):
    s.extend([i])
  return s

# s is bytes to pad, k is blocklength
# you won't need to change the block length
def cmsc284padbytes(s,k=16):
  if k > 255:
    raise Exception("pkcs7pad: padding block length must be less than 256")
  n = k - (len(s) % k)
  if n == 0:
    n = k
  for i in range(1,n+1):
    s += chr(i).encode("utf-8")
  return s

# s is bytes to unpad, k is blocklength
# you won't need to change the block length
def cmsc284unpad(s,k=16):
  if not cmsc284checkpadding(s,k):
    print("cmsc284unpad: invalid padding")
    return b''
  n = s[len(s)-1]
  return s[:len(s)-n]

# checks padding on s and returns a boolean
# you won't need to change the block length
def cmsc284checkpadding(s,k=16):
  if(len(s) == 0):
    #print("Invalid padding: String zero length"%k) 
    return False
  if(len(s)%k != 0): 
    #print("Invalid padding: String is not multiple of %d bytes"%k) 
    return False
  n = s[len(s)-1]
  if n > k or n == 0:
    return False
  else: 
    for i in range(n):
      if s[len(s)-1-i] != (n-i):
        return False
  return True

################################################################################
# Function for querying the server
################################################################################

def make_query(task, cnetid, query):
  DEBUG = False
  if DEBUG:
    print("making a query")
    print("Task:", task)
    print("CNET ID:", cnetid)
    print("Query:", query)
  if (type(query) is bytearray) or (type(query) is bytes):
    url = PPS2SERVER + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnetid) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query)) + "/"
  else:
    url = PPS2SERVER + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnetid) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query.encode('utf-8'))) + "/"
  if DEBUG:
    print("Querying:", url)

  with urllib.request.urlopen(url) as response:
    raw_answer = response.read()
    answer = base64.urlsafe_b64decode(raw_answer)
    if DEBUG:
      print("Answer:", answer)
    return answer
  return None

################################################################################
# Problem 1 SOLUTION
################################################################################

def problem1(cnetid):
  flag_len = len(make_query('one', cnetid, b''))
  bias_idx = 30

  flag_ints = []
  for i in range(flag_len):
    zeros_query = bytearray(bias_idx - i)
    flag_candidates = []
    for _ in range(150):
      ctext = make_query('one', cnetid, zeros_query)
      flag_candidates.append(ctext[bias_idx])
    counts = Counter(flag_candidates)
    byte_int = counts.most_common(1)[0][0]
    flag_ints.append(byte_int)
    if VERBOSE:
      print(i, bytes([byte_int]))
  return bytes(flag_ints)

################################################################################
# Problem 2 SOLUTION
################################################################################

def problem2(cnetid):
  ctext_a = make_query('twoa', cnetid, '')
  ctext_prof = ctext_a[32:]
  query_b = b'davidcausername=' + bytes('ruolinzheng', 'utf-8') + b'&uid=8'
  ctext_b = make_query('twob', cnetid, query_b)
  query_c = ctext_b[16:48] + ctext_prof
  return make_query('twoc', cnetid, query_c)

################################################################################
# Problem 3 SOLUTION
################################################################################

def get_flag_len(cnetid):
  """get unpadded flag len"""
  padded_flag_len = len(make_query('three', cnetid, ''))
  flag_len = -1
  prev = -1
  for i in range(1, 17):
    curr = len(make_query('three', cnetid, bytes(i)))
    if prev == padded_flag_len and curr == padded_flag_len + 16:
      flag_len = padded_flag_len - i
      break
    prev = curr
  return flag_len

def get_byte_map(cnetid, prev_bytes):
  # should feed this function prev_bytes[:16]
  if len(prev_bytes) > 16:
    raise
  mp = {}
  for i in range(256):
    query_bytes = bytes([i]) + prev_bytes
    query = cmsc284padbytes(query_bytes)
    ctext = make_query('three', cnetid, query)
    # always only need the first block
    mp[ctext[:16]] = query_bytes
  return mp

def get_block_loc(flag_len):
  """get start pos of the target block"""
  block_idx = math.ceil((flag_len - 1) / 16)
  start = 16 * block_idx
  return start

def get_first_query_len(flag_len):
  """get the length of the first query, [0, 15]"""
  return (16 - (flag_len - 1) % 16) % 16

def problem3(cnetid):
  flag_len = get_flag_len(cnetid)
  start = get_block_loc(flag_len)
  first_query_len = get_first_query_len(flag_len)
  if VERBOSE:
    print('flag len, start, first_query_len:',
          flag_len, start, first_query_len)
  prev_bytes = b''
  for i in range(flag_len):
    byte_mp = get_byte_map(cnetid, prev_bytes[:16])
    query = bytes(first_query_len + len(prev_bytes))
    ctext = make_query('three', cnetid, query)
    new_bytes = byte_mp[ctext[start : start + 16]]
    prev_bytes = bytes([new_bytes[0]]) + prev_bytes
    if VERBOSE:
      print(i, prev_bytes)
  return prev_bytes

################################################################################
# Problem 4 SOLUTION
################################################################################

def xor_bytes(bytes1, bytes2):
  if len(bytes1) != len(bytes2):
    raise
  return bytes([b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)])

def get_key(cnetid):
  ctext_b = make_query('fourb', cnetid, bytes(32))
  m1, m2 = ctext_b[:16], ctext_b[16:]
  key = xor_bytes(m1, m2)
  return key

def problem4_enc(key, msg):
  padded_msg = cmsc284padbytes(msg)
  parsed_msgs = [padded_msg[i : i + 16] for i in 
                 range(0, len(padded_msg), 16)]
  ctexts = [key]
  cipher = AES.new(key, AES.MODE_ECB)
  for i in range(len(parsed_msgs)):
    to_encrypt = xor_bytes(ctexts[i], parsed_msgs[i])
    ctexts.append(cipher.encrypt(to_encrypt))
  return b''.join(ctexts[1:]) # omit ctexts[0] which is the key

def problem4(cnetid):
  msg = b'let me in please'
  key = get_key(cnetid)
  query = problem4_enc(key, msg)
  return make_query('fourc', cnetid, query)

################################################################################
# Problem 5 SOLUTION
################################################################################

def get_aes_dec_byte(cnetid, ctext, idx):
  """modify ctext in place and
  return dec_byte = AES^{-1}(k, c[i])[idx]"""
  dec_byte = None
  for byte in range(1, 256):
    ctext[idx] = byte
    resp = make_query('fiveb', cnetid, ctext)
    if resp == b'true':
      dec_byte = ctext[idx] ^ 1
      break
  return dec_byte

def set_ctext(ctext, recovered, start, end):
  """modify ctext in place"""
  for i in range(end - start):
    offset = start + i
    byte = (i + 2) % 256 # wrap around
    ctext[offset] = recovered[offset] ^ byte

def problem5(cnetid):
  ctext = bytearray(make_query('fivea', cnetid, ''))
  len_ctext = len(ctext)
  len_flag = len_ctext - 16
  aes_dec_arr = bytearray(len_flag)
  flag_arr = bytearray(len_flag)
  # first block can't be used on its own
  for block_idx in range(len_ctext, 16, -16):
    ctext_mod = ctext[:block_idx] # new copy
    offset = len(ctext_mod) - 16
    for idx in range(offset - 1, offset - 17, -1):
      dec_byte = get_aes_dec_byte(cnetid, ctext_mod, idx)
      aes_dec_arr[idx] = dec_byte
      flag_arr[idx] = dec_byte ^ ctext[idx]
      if VERBOSE:
        print(idx, bytes([flag_arr[idx]]))
      set_ctext(ctext_mod, aes_dec_arr, idx, offset)
  if not cmsc284checkpadding(flag_arr):
    raise
  else:
    return cmsc284unpad(flag_arr)

################################################################################
# Problem 6 SOLUTION
################################################################################

def problem6(cnetid):
  ctext = make_query('six', cnetid, '')
  flag_len = len(ctext) - len(zlib.compress(b'password=;userdata='))
  flag = bytearray()
  for i in range(flag_len):
    min_len = None
    for b in range(256):
      byte = bytes([b])
      query = b'password=' + bytes(flag) + byte
      ctext = make_query('six', cnetid, query)
      len_ctext = len(ctext)
      if min_len is None:
        min_len = len_ctext
      elif min_len > len_ctext:
        flag.append(b)
        if VERBOSE:
          print(i, b, byte, flag)
        break
    if flag[-1] == ord(';'): # reach end of password=FLAG;
      return flag[:-1]
  return flag[:flag.find(b';')]

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--verbose', '-v', action='store_true')
  parser.add_argument('--cnetid', '-c', type=str)
  parser.add_argument('--problem', '-p', type=int)
  args = parser.parse_args()
  if not args.cnetid:
    cnetid = 'ruolinzheng'
  else:
    cnetid = args.cnetid
  global VERBOSE
  VERBOSE = args.verbose
  if args.problem is None or args.problem == 1:
    print('### Problem 1')
    print(problem1(cnetid))
  if args.problem is None or args.problem == 2:
    print('### Problem 2')
    print(problem2(cnetid))
  if args.problem is None or args.problem == 3:
    print('### Problem 3')
    print(problem3(cnetid))
  if args.problem is None or args.problem == 4:
    print('### Problem 4')
    print(problem4(cnetid))
  if args.problem is None or args.problem == 5:
    print('### Problem 5')
    print(problem5(cnetid))
  if args.problem is None or args.problem == 6:
    print('### Problem 6')
    print(problem6(cnetid))

if __name__ == '__main__':
  main()