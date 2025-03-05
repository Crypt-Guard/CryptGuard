# 🗺️ CryptGuard - RoadMap & Funcionalidades

## 📋 Menu Principal

O CryptGuard atualizado oferece as seguintes funcionalidades principais:

| Opção | Funcionalidade |
|-------|----------------|
| 1️⃣   | Criptografar Texto |
| 2️⃣   | Criptografar Arquivo (Imagem/PDF/Áudio) |
| 3️⃣   | Descriptografar Arquivo |
| 4️⃣   | Criptografar Múltiplos Arquivos |
| 5️⃣   | Gerar Token Efêmero |
| 6️⃣   | Criar Volume Oculto (Negação Plausível) |
| 7️⃣   | Re-Encrypt (Key Rolling - Volume Normal) |
| 8️⃣   | Trocar Senha do Volume Real (Hidden) |
| 0️⃣   | Sair |

---

## 🔒 Detalhamento das Funcionalidades

### 1️⃣ Criptografar Texto

#### Fluxo de Operação
1. **Entrada de Texto**  
   - O usuário digita a mensagem a ser criptografada.

2. **Autenticação**  
   - O usuário escolhe entre "Senha + Arquivo-chave" ou "Somente Senha" (com dupla verificação).

3. **Processo de Criptografia**  
   - Utiliza o modo single-shot (`encrypt_data_single`).
   - Deriva a chave via Argon2id e criptografa com ChaCha20Poly1305.
   - Metadados cifrados (incluindo a extensão original) são armazenados em um arquivo `.meta`.

4. **Resultado**  
   - O arquivo criptografado é salvo em `~/Documents/Encoded_files_folder` com a extensão especificada.

---

### 2️⃣ Criptografar Arquivo

#### Fluxo de Operação
1. **Seleção do Arquivo**  
   - O usuário informa o caminho do arquivo.

2. **Autenticação**  
   - Escolha entre "Senha + Arquivo-chave" ou "Somente Senha".

3. **Verificação de Tamanho**  
   - Se o arquivo for maior que um threshold (ex.: 10 MB), utiliza o modo streaming (`encrypt_data_streaming`) com chunk size dinâmico.
   - Caso contrário, utiliza o modo single-shot.

4. **Processo**  
   - Geração do arquivo criptografado e dos metadados cifrados.

5. **Resultado**  
   - Arquivo salvo com a extensão original preservada.

---

### 3️⃣ Descriptografar Arquivo

#### Fluxo de Operação
1. **Listagem e Seleção**  
   - Exibe os arquivos `.enc` disponíveis.
2. **Autenticação**  
   - Escolha entre "Senha + Arquivo-chave" ou "Somente Senha".
3. **Processamento**  
   - Leitura dos metadados cifrados para recuperar os parâmetros de criptografia.
   - Seleção do método de descriptografia (single-shot ou streaming).
   - Para volumes ocultos, solicitação de token efêmero e escolha entre volume falso ou real.
4. **Resultado**  
   - Arquivo descriptografado é salvo com a extensão original (por exemplo, `.txt`, `.jpg`).

---

### 4️⃣ Criptografar Múltiplos Arquivos

#### Fluxo de Operação
1. **Seleção**  
   - O usuário insere múltiplos caminhos de arquivo.
2. **Compactação**  
   - Criação de um arquivo ZIP temporário com os arquivos selecionados.
3. **Autenticação**  
   - Escolha entre "Senha + Arquivo-chave" ou "Somente Senha".
4. **Processo**  
   - Se o ZIP for grande, utiliza o modo streaming (com chunk size dinâmico); caso contrário, single-shot.
5. **Resultado**  
   - O arquivo ZIP criptografado é salvo com metadados que preservam a extensão original.

---

### 5️⃣ Gerar Token Efêmero

#### Fluxo de Operação
1. **Geração**  
   - Um token hexadecimal com 128 bits de entropia é gerado via `generate_ephemeral_token`.
2. **Utilidade**  
   - Utilizado para acesso a volumes ocultos e proteção da parte "real" dos dados.
3. **Resultado**  
   - O token é exibido para o usuário.

---

### 6️⃣ Criar Volume Oculto (Negação Plausível)

#### Fluxo de Operação
1. **Seleção de Arquivos**  
   - O usuário fornece dois conjuntos de arquivos: um para o volume falso e outro para o volume real.
2. **Autenticação**  
   - São configuradas senhas distintas para cada volume (usando "Senha + Arquivo-chave" ou "Somente Senha").
3. **Processo**  
   - Cada conjunto é criptografado individualmente via `encrypt_data_raw_chacha`.
   - As partes (volume falso, padding e volume real) são concatenadas e codificadas com Reed-Solomon.
   - Um token efêmero é gerado para acesso à parte real.
4. **Resultado**  
   - O volume oculto é criado, mantendo a integridade dos dados e sem expor a parte real.

---

### 7️⃣ Re-Encrypt (Key Rolling - Volume Normal)

#### Fluxo de Operação
1. **Seleção**  
   - O usuário seleciona um arquivo criptografado de um volume normal.
2. **Processo**  
   - O arquivo é descriptografado usando a senha antiga, gerando um arquivo com a extensão original.
   - O usuário fornece uma nova senha para recriptografar o arquivo.
3. **Resultado**  
   - Um novo arquivo criptografado é gerado, preservando a extensão original, e o usuário pode optar por remover o arquivo antigo.

---

### 8️⃣ Trocar Senha do Volume Real (Hidden)

#### Fluxo de Operação
1. **Seleção do Volume Oculto**  
   - O usuário seleciona um volume oculto.
2. **Autenticação**  
   - Inicialmente, a senha do volume falso é utilizada para acessar os metadados.
   - Em seguida, o usuário insere a senha atual do volume real para decifrar a parte real.
3. **Re-Keying**  
   - A parte real é decifrada em memória.
   - O usuário fornece uma nova senha para recriptografar somente a parte real.
   - O volume é reconstruído, mantendo inalterada a parte falsa e o padding.
4. **Resultado**  
   - O volume oculto é atualizado com a nova senha para a parte real, sem expor os dados sensíveis.

---

### 0️⃣ Sair

- Encerra a execução do programa de forma segura.

---

Este RoadMap reflete a versão atual do CryptGuard, com sua nova estrutura modular e as funcionalidades implementadas, incluindo a troca de senha do volume real (key rolling), chunk size dinâmico para arquivos grandes e as opções de autenticação baseadas em senha.
