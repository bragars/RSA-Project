"""
  Gerador e verificador de assinaturas RSA em ARQUIVOS
  Trabalho SC - 2022
  Matricula - 180107992
  Nome: Pedro Braga
"""

from aes.aes import encrypt_file, decrypt_file
from rsa import choose_keys
import hashlib
import base64
import rsa
import time
import math

def countBits(number):
    return int((math.log(number) / math.log(2)) + 1)

"""
  Parte I:  Geração de chaves e cifra simétrica

  a) Geração de chaves (p e q primos com no mínimo de 1024 bits)

  inside chooseKeys method on rsa.py file

  prime_list = primesInRange(100, 1000)
  prime1 = random.choice(prime_list)
  prime2 = random.choice(prime_list).
"""

start_time = time.time()
p, q = choose_keys()
print("p e q primos, respectivamente", countBits(p), countBits(q))

"""
  b) Geração de chave simétrica de sessão
  AES-128 has 128 bit key = 16 bytes.
"""

# session_key = os.urandom(16)
session_key = b'\x18\x86\x92\xc2\x9e\x9fz\x8c\xafc\xb0\xa7\xbf\x88\xf0r'
print("Geração de chave simétrica de sessão", session_key)
print("")

"""
  c) Cifração simétrica de mensagem (AES modo CTR)
  And assign of files
"""

i_file_encrypt = 'aes/files/file1.txt'
o_file_encrypt = 'aes/files/file1.txt.aes'
o_file_decrypt = 'aes/files/file1_output.txt'

encrypt_file(i_file_encrypt, session_key.hex(), o_file_encrypt)

"""
  d) Cifração assimétrica da chave de sessão, usando OAEP.

  OAEP satisfies the following two goals:
  o Add an element of randomness which can be used to convert a deterministic encryption scheme (e.g., traditional RSA)
    into a probabilistic scheme.
  o Prevent partial decryption of ciphertexts (or other information leakage) by ensuring that an
    adversary cannot recover any portion of the plaintext without being able to invert the trapdoor one-way permutation

  Encrypt with the public_keys, that way the sender and the receiver can communicate
  Encrypting with the public key the receiver can decrypt with his secret key, that way
  Only the sender and the receiver know the session key  
"""

session_key_decoded = session_key.decode('iso-8859-15')
encodedBytes = base64.b64encode(session_key)
signature_encoded_64 = str(encodedBytes, "utf-8")
session_key_encrypted = rsa.encrypt(signature_encoded_64)

"""
  Parte II: Assinatura
  1) Cálculo de hashes da mensagem em claro (função de hash SHA-3)
"""

with open('aes/files/file1.txt', 'rb') as f:
  plaintext = f.read()

plaintext = plaintext.decode('utf-8')
sha3_224 = hashlib.sha3_224()
sha3_224.update(plaintext.encode())
plain_text_hash = sha3_224.hexdigest()
print("Cálculo de hashes da mensagem em claro", plain_text_hash)
print("")

"""
  2) Assinatura da mensagem (cifração do hash da mensagem) - com a chave privada
  Uma vez computada uma message digest, criptografa-se o hash gerado com uma chave privada
"""

signature = rsa.encrypt(plain_text_hash, 'keys/private_keys.txt')
print("Assinatura da mensagem (cifração do hash da mensagem)", signature)
print("")

"""
  3) Formatação do resultado (caracteres especiais e informações para verificação em BASE64)
"""

encodedBytes = base64.b64encode(signature.encode("utf-8"))
signature_encoded_64 = str(encodedBytes, "utf-8")
print("3) Formatação do resultado (caracteres especiais e informações para verificação em BASE64)", signature_encoded_64)
print("")

"""
  Parte III: Verificação:

  1) Parsing do documento assinado(de acordo com a formatação usada, no caso BASE64)
  Decifração da mensagem
  
  First the receiver decrypt the session key with his secret key
  And uses to decrypt the message using AES decrypt method
"""

# Always here
session_key_decrypted = rsa.decrypt(session_key_encrypted)

# session_key_decrypted = base64.b64decode(session_key_decrypted)
session_key_decrypted = base64.urlsafe_b64decode(session_key_decrypted)

try:
  session_key_decrypted.decode('utf-16')
  session_key_decrypted = base64.urlsafe_b64decode(session_key_decrypted).decode()
  decrypted = decrypt_file(o_file_encrypt, session_key_decrypted.hex(), o_file_decrypt)
except:
  session_key_decrypted = session_key_decrypted.hex()
  decrypted = decrypt_file(o_file_encrypt, session_key_decrypted, o_file_decrypt)

# session_key_decrypted = session_key_decrypted.encode('iso-8859-15')

"""
  2) Decifração da assinatura (decifração do hash)
"""

signature_parsing = base64.urlsafe_b64decode(signature_encoded_64).decode()
decrypted_signature = rsa.decrypt(signature_parsing, 'keys/public_keys.txt')
print("decrypted_signature", decrypted_signature)
print("")

"""
  3) Verificação (cálculo e comparação do hash do arquivo)

  Check if the hash is equal to the message for integrity
  If is true, the hash comparation proves that the message doens't get modifications
"""

decrypted = decrypted.decode('utf-8')
sha3_224 = hashlib.sha3_224()
sha3_224.update(decrypted.encode())
decrypted_hash = sha3_224.hexdigest()
print("Cálculo de hashes da mensagem decifrada", decrypted_hash)

print("")
print("Mensagem decifrada", decrypted)
print("")

if (decrypted_hash == plain_text_hash):
  print("Integrity is confirmed. Without changes")
else:
  print("Is not the same hash, someone corrupt the file.")

print("--- %s seconds ---" % (time.time() - start_time))