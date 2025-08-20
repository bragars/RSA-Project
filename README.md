# Projeto - Segurança Computacional  
**Gerador e verificador de assinaturas RSA em arquivos**

---

## Introdução  
O AES-CTR, conhecido por seu nome original **Rijndael**, é utilizado para criptografia de dados eletrônicos e foi estabelecido pelo **Instituto Nacional de Padrões e Tecnologia (NIST)** dos EUA em 2001.  

---

## Parte I: Geração de chaves e cifra simétrica  

### a) Geração de chaves (RSA)  
- Seleciona dois números primos aleatórios grandes (**p** e **q**) com no mínimo 1024 bits para iniciar o RSA.  

### b) Geração de chave simétrica de sessão  
- Gera chave de sessão de **128 bits (16 bytes)** utilizada para a cifra com o AES.  

### c) Cifração simétrica de mensagem (AES modo CTR)  
1. O arquivo texto é lido e a mensagem é criptografada.  
2. A criptografia simétrica é convertida em **BASE64**.  
3. O output é inserido no arquivo `file.txt.aes`.  

### d) Cifração assimétrica da chave de sessão (RSA + OAEP)  
- A chave de sessão é criptografada com a **chave pública**.  
- Chaves públicas e privadas são criadas a partir do RSA.  

---

## Parte II: Assinatura  

### a) Cálculo de hash da mensagem  
- Utiliza a função **SHA-3** para gerar o hash da mensagem em claro.  
- O hash serve para **verificação de integridade**.  

### b) Assinatura da mensagem  
- O hash da mensagem é criptografado com a **chave privada**.  

### c) Formatação do resultado  
- A assinatura é convertida para **BASE64**.  

---

## Parte III: Verificação  

### a) Parsing do documento assinado  
- A assinatura em BASE64 é decodificada de volta para a mensagem original.  
- Durante a decifração, a função `decrypt` faz o parsing da BASE64.  

### b) Decifração da assinatura  
- A assinatura é decifrada.  
- A chave de sessão é usada para decifrar o arquivo `file.txt.aes`.  

### c) Verificação do hash  
- O hash do arquivo recebido é comparado ao hash original.  
- Se forem iguais, a integridade da troca de mensagens é garantida.  

---

## Funções do AES  

- **key_expansion** → Gera 44 palavras baseado na chave inicial.  
- **add_round_key**  
- **shift_rows**  
- **mix_columns**  
- **encrypt** → Aplica todas as funções descritas em 10 rounds, começando com `add_round_key`, seguido de:  
  1. `sub_bytes`  
  2. `shift_rows`  
  3. `mix_columns`  
  4. `add_round_key`  
  - No último round, **não é utilizado** o `mix_columns`.  

- **decrypt** → Aplica todas as funções descritas em 10 rounds:  
  1. `inv_sub_bytes`  
  2. `inv_shift_rows`  
  3. `inv_mix_columns`  
  4. `add_round_key`  
  - No último round, **não é utilizado** o `inv_mix_columns`.  

---

## RSA  

O RSA utiliza o algoritmo de **Diffie-Hellman** como base.  

1. Escolhe dois números primos grandes (**p**, **q**).  
2. Calcula o produto: `n = p * q`.  
3. Calcula a função totiente de Euler:  
   \[
   \varphi(n) = (p - 1)(q - 1)
   \]  
4. Escolhe um número **e** que seja coprimo de *n*, utilizando o algoritmo de Euclides.  
5. Calcula **d**, onde `ed ≡ 1 (mod ϕ(n))` (algoritmo de Euclides estendido).  
   - **d** é a chave privada.  
6. **Criptografia:**  
   \[
   c = m^e \mod n
   \]  
7. **Decifração:**  
   \[
   m = c^d \mod n
   \]  

---
