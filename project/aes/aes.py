from aes.constants import sbox, isbox, gfp2, gfp3, gfp9, gfp11, gfp13, gfp14, Rcon

import sys
import base64
import os

def key_expansion(w, bytes_number=4, key_number=4, rounds_number=10, counter=4):
  """
    Key Expansion routine to generate a key schedule.
    Generates 44 words
  """

  while counter < bytes_number * (rounds_number + 1):
    temp = w[counter-1][:]
    if counter % key_number == 0:
      temp = sub_word(rot_word(temp))
      temp[0] ^= Rcon[(counter // key_number)]
    elif key_number > 6 and counter % key_number == 4:
      temp = sub_word(temp)

    for j in range(len(temp)):
      temp[j] ^= w[counter-key_number][j]

    w.append(temp[:])
    counter+=1
  return w

def add_round_key(state, key):
  Nb = len(state)
  new_state = [[None for j in range(4)] for i in range(Nb)]

  for i, word in enumerate(state):
    for j, byte in enumerate(word):
      new_state[i][j] = byte ^ key[i][j]

  return new_state

def shift_rows(state):
  Nb = len(state)
  n = [word[:] for word in state]

  for i in range(Nb):
    for j in range(4):
      n[i][j] = state[(i+j) % Nb][j]

  return n

def inv_shift_rows(state):
  Nb = len(state)
  n = [word[:] for word in state]

  for i in range(Nb):
    for j in range(4):
      n[i][j] = state[(i-j) % Nb][j]

  return n

def mix_columns(state):
  Nb = len(state)
  n = [word[:] for word in state]

  for i in range(Nb):
    n[i][0] = (gfp2[state[i][0]] ^ gfp3[state[i][1]]
              ^ state[i][2] ^ state[i][3])
    n[i][1] = (state[i][0] ^ gfp2[state[i][1]]
              ^ gfp3[state[i][2]] ^ state[i][3])
    n[i][2] = (state[i][0] ^ state[i][1]
              ^ gfp2[state[i][2]] ^ gfp3[state[i][3]])
    n[i][3] = (gfp3[state[i][0]] ^ state[i][1]
              ^ state[i][2] ^ gfp2[state[i][3]])

  return n

def inv_mix_columns(state):
  Nb = len(state)
  n = [word[:] for word in state]

  for i in range(Nb):
      n[i][0] = (gfp14[state[i][0]] ^ gfp11[state[i][1]]
                ^ gfp13[state[i][2]] ^ gfp9[state[i][3]])
      n[i][1] = (gfp9[state[i][0]] ^ gfp14[state[i][1]]
                ^ gfp11[state[i][2]] ^ gfp13[state[i][3]])
      n[i][2] = (gfp13[state[i][0]] ^ gfp9[state[i][1]]
                ^ gfp14[state[i][2]] ^ gfp11[state[i][3]])
      n[i][3] = (gfp11[state[i][0]] ^ gfp13[state[i][1]]
                ^ gfp9[state[i][2]] ^ gfp14[state[i][3]])

  return n

def cipher(block, w, Nb=4, Nk=4, Nr=10):
  state = add_round_key(block, w[:Nb])

  for r in range(1, Nr):
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, w[r*Nb:(r+1)*Nb])

  state = sub_bytes(state)
  state = shift_rows(state)
  state = add_round_key(state, w[Nr*Nb:(Nr+1)*Nb])

  return state

def inv_cipher(block, w, Nb=4, Nk=4, Nr=10):
  state = add_round_key(block, w[Nr*Nb:(Nr+1)*Nb])

  for r in range(Nr-1, 0, -1):
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, w[r*Nb:(r+1)*Nb])
    state = inv_mix_columns(state)

  state = inv_shift_rows(state)
  state = inv_sub_bytes(state)
  state = add_round_key(state, w[:Nb])

  return state

def rot_word(word):
  """
    Takes a word as input, performs a cyclic permutation and return the word
    Ex: [a0, a1, a2, a3] => [a1, a2, a3, a0]
  """
  return word[1:] + word[0:1]

def sub_word(word):
  """
    Function that takes a four-byte input word and applies the S-box
    to each of the four bytes to produce and output word
  """
  return [sbox[byte] for byte in word]

def sub_bytes(state):
  """
    Is a non-linear byte substitution that operates independently
    on each byte of the State using a substitution table (S-box)
  """
  return [[sbox[byte] for byte in word] for word in state]

def inv_sub_bytes(state):
  """
    Is the inverse of the sub_bytes
    Si(Si-box) is the inverse of the S(S-box)
  """
  return [[isbox[byte] for byte in word] for word in state]

def process_key(key, Nk=4):
  key = key.replace(" ", "")
  return [[int(key[i*8+j*2:i*8+j*2+2], 16) for j in range(4)] for i in range(Nk)]

def process_block(block, Nb=4):
  if type(block) == str:
    block = bytes(block, 'utf8')
  pass

  return [[block[i*4+j] for j in range(4)] for i in range(Nb)]

def str_block_line(block):
  s = ''

  for i in range(len(block)):
    for j in range(len(block[0])):
      h = hex(block[i][j])[2:]
      if len(h) == 1:
        h = '0'+h
      s += h
  return (s)

def padding(inf, Nb=4):
  ''' PKCS#7 padding '''
  padding_length = (Nb*4) - (len(inf) % (Nb*4))

  if padding_length:
    if isinstance(inf, str):  # Python 2
      inf += chr(padding_length) * padding_length
    elif isinstance(inf, bytes):  # Python 3
      inf += bytes([padding_length] * padding_length)

  return inf

def get_block(inf, Nb=4):
  return process_block(inf[:Nb*4], Nb), inf[Nb*4:]

def prepare_block(block):
  c = []
  for word in block:
    for byte in word:
      c.append(byte)

  s = None
  for byte in c:
    if not s:
      s = bytes([byte])
    else:
      s += bytes([byte])

  return s

def unpadding(inf, Nb=4):
  ''' PKCS#7 padding '''
  inf = inf.decode('utf-8')
  padding_length = ord(inf[-1])
  if padding_length < (Nb*4):
    if len(set(inf[-padding_length:])) == 1:
      inf = inf[:-padding_length]

  return inf.encode('utf-8')

def encrypt_file(ifile, key, ofile):
  Nb = 4
  Nk = 4
  Nr = 10

  Nr = Nk + 6
  key = key.replace(' ', '')

  try:
    with open(ifile, 'rb') as f:
      inf = f.read()
  except:
    print ("Error while trying to read input file.")
    sys.exit()

  key = process_key(key, Nk)
  expanded_key = key_expansion(key, Nb, Nk, Nr)

  output = None

  inf = padding(inf, Nb)

  while inf:
    block, inf = get_block(inf, Nb)
  
    block = cipher(block, expanded_key, Nb, Nk, Nr)
    block = prepare_block(block)

    if output:
      output += block
    else:
      output = block

  with open(ofile, 'wb') as f:
    session_key_decoded = output.decode('iso-8859-15')
    encodedBytes = base64.b64encode(session_key_decoded.encode("utf-8"))
    signature_encoded_64 = str(encodedBytes, "utf-8")
    f.write(signature_encoded_64.encode("utf-8"))

def decrypt_file(ifile, key, ofile):
  Nb = 4
  Nk = 4
  Nr = 10

  try:
    with open(ifile, 'rb') as f:
      inf = f.read()
  except:
    print ("Error while trying to read input file.")
    sys.exit()

  session_key_decrypted = base64.urlsafe_b64decode(inf).decode()
  inf = session_key_decrypted.encode('iso-8859-15')

  key = process_key(key, Nk)
  expanded_key = key_expansion(key, Nb, Nk, Nr)

  output = None

  while inf:
    block, inf = get_block(inf, Nb)

    block = inv_cipher(block, expanded_key, Nb, Nk, Nr)
    block = prepare_block(block)

    if output:
      output += block
    else:
      output = block

  output = unpadding(output, Nb)

  with open(ofile, 'wb') as f:
    f.write(output)
  return output

def main_file(key):
  encrypt_file('files/file.txt', key, 'files/file.txt.aes')
  decrypt_file('files/file.txt.aes', key, 'files/file_output.txt')

if __name__ == '__main__':
  key = os.urandom(16).hex()
  main_file(key)
