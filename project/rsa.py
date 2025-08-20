import random

def gcd(a, b):
  """
  Greatest Common Divisor
  """
  if (b == 0):
    return a
  else:
    return gcd(b, a % b)

def xgcd(a, b):
  """
  Extended Euclidean algorithm
  Returns the gcd, coefficient of a, and coefficient of b
  """
  x, old_x = 0, 1
  y, old_y = 1, 0

  while (b != 0):
    quotient = a // b
    a, b = b, a - quotient * b
    old_x, x = x, old_x - quotient * x
    old_y, y = y, old_y - quotient * y

  return a, old_x, old_y

def primesInRange(x, y):
  """
  Selects one random prime number from a range of numbers
  """
  prime_list = []
  for n in range(x, y):
    isPrime = True

    for num in range(2, n):
      if n % num == 0:
        isPrime = False

    if isPrime:
      prime_list.append(n)

  return prime_list

def compute_e(totient):
  """
  Chooses a coprime random number, 1 < e < totient, gcd(e, totient) = 1
  """
  while (True):
    e = random.randrange(2, totient)

    if (gcd(e, totient) == 1):
      return e

def choose_keys():
  # Geração de chaves (p e q primos com no mínimo de 1024 bits)
  prime_list = primesInRange(100, 1000)
  # p = int(random.getrandbits(100)) generates 1024 bits
  # q = int(random.getrandbits(100)) generates 1024 bits
  p = random.choice(prime_list)
  q = random.choice(prime_list)

  n = p * q
  totient = (p - 1) * (q - 1)
  e = compute_e(totient)

  # ed = 1 (mod totient)
  gcd, x, y = xgcd(e, totient)

  if (x < 0):
    d = x + totient
  else:
    d = x

  # write the public keys
  f_public = open('keys/public_keys.txt', 'w')
  f_public.write('-----BEGIN PGP PUBLIC KEY BLOCK-----' + '\n' + str(n) + '\n')
  f_public.write(str(e) + '\n' + '-----END PGP PUBLIC KEY BLOCK-----')
  f_public.close()

  # write the private keys
  f_private = open('keys/private_keys.txt', 'w')
  f_private.write('-----BEGIN PGP PRIVATE KEY BLOCK-----' + '\n' + str(n) + '\n')
  f_private.write(str(d) + '\n' + '-----END PGP PRIVATE KEY BLOCK-----')
  f_private.close()

  return p, q

def encrypt(message, file_name = 'keys/public_keys.txt', block_size = 2):
    try:
      fo = open(file_name, 'r')

    except FileNotFoundError:
      print('That file is not found.')
    else:
      # used to read the -----BEGIN PGP PUBLIC KEY BLOCK-----
      public_key_begin = fo.readline()
      n = int(fo.readline())
      e = int(fo.readline())
      # used to read the -----END PGP PUBLIC KEY BLOCK-----
      public_key_end = fo.readline()
      fo.close()

      # initialize the encrypted_blocks
      encrypted_blocks = []
      ciphertext = -1

      if (len(message) > 0):
        ciphertext = ord(message[0])

      for i in range(1, len(message)):
        if (i % block_size == 0):
          encrypted_blocks.append(ciphertext)
          ciphertext = 0

        ciphertext = ciphertext * 1000 + ord(message[i])

      # array to push every encrypted block
      encrypted_blocks.append(ciphertext)

      for i in range(len(encrypted_blocks)):
        encrypted_blocks[i] = str((encrypted_blocks[i]**e) % n) # 2^7(mod 55) = 18

      encrypted_message = " ".join(encrypted_blocks)

      # returns all encrypted blocks
      return encrypted_message

def decrypt(blocks, file_name = 'keys/private_keys.txt', block_size = 2):
  fo = open(file_name, 'r')
  # used to read the -----BEGIN PGP PRIVATE KEY BLOCK-----
  private_key_begin = fo.readline()
  n = int(fo.readline())
  d = int(fo.readline())
  # used to read the -----BEGIN PGP PRIVATE KEY BLOCK-----
  private_key_end = fo.readline()

  fo.close()

  list_blocks = blocks.split(' ')
  int_blocks = []

  for s in list_blocks:
    int_blocks.append(int(s))

  message = ""

  for i in range(len(int_blocks)):
    # 18^23 (mod 55) = 2

    int_blocks[i] = (int_blocks[i]**d) % n

    aux = ""

    for c in range(block_size):
      aux = chr(int_blocks[i] % 1000) + aux
      int_blocks[i] //= 1000
    message += aux

  return message
