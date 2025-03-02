# 🗺️ CryptGuard - RoadMap & Funcionalidades

## 📋 Menu Principal

O CryptGuard oferece as seguintes funcionalidades principais:

| Opção | Funcionalidade |
|-------|---------------|
| 1️⃣ | Criptografar Texto |
| 2️⃣ | Criptografar Arquivo (Imagem/PDF/Áudio) |
| 3️⃣ | Descriptografar Arquivo |
| 4️⃣ | Criptografar Múltiplos Arquivos |
| 5️⃣ | Gerar Token Efêmero |
| 6️⃣ | Criar Volume Oculto (Negação Plausível) |
| 0️⃣ | Sair |

## 🔒 Detalhamento das Funcionalidades

### 1️⃣ Criptografar Texto

#### Fluxo de Operação
1. **Entrada de Texto**
   - O usuário digita a mensagem a ser criptografada

2. **Arquivo-chave (Opcional)**
   - Opção de usar arquivo-chave para aumentar a entropia da senha

3. **Senha**
   - Validação de requisitos:
     - Mínimo 8 caracteres
     - Letras maiúsculas/minúsculas
     - Dígitos e caracteres especiais
     - Avaliação via zxcvbn

4. **Processo de Criptografia**
   - Utiliza `encrypt_data_single`
   - Derivação de chave via Argon2id
   - Criptografia autenticada com ChaCha20Poly1305
   - Metadados armazenados em arquivo `.meta` cifrado

5. **Resultado**
   - Arquivo salvo em `~/Documents/Encoded_files_folder`
   - Confirmação de sucesso

### 2️⃣ Criptografar Arquivo

#### Fluxo de Operação
1. **Seleção do Arquivo**
   - Usuário informa o caminho do arquivo

2. **Arquivo-chave (Opcional)**
   - Opção para aumentar a entropia

3. **Verificação de Tamanho**
   - \> 10 MB: Criptografia em streaming (`encrypt_data_streaming`)
   - ≤ 10 MB: Criptografia single-shot (`encrypt_data_single`)

4. **Processo**
   - Geração do arquivo criptografado
   - Criação do arquivo de metadados (.meta)

5. **Resultado**
   - Arquivo salvo na pasta padrão
   - Confirmação de sucesso

### 3️⃣ Descriptografar Arquivo

#### Fluxo de Operação
1. **Listagem**
   - Exibe arquivos `.enc` em `~/Documents/Encoded_files_folder`

2. **Seleção**
   - Escolha do arquivo a ser descriptografado

3. **Arquivo-chave**
   - Validação se aplicável

4. **Processamento**
   - Leitura do arquivo `.meta`
   - Identificação dos parâmetros
   - Escolha do método de descriptografia

5. **Decriptação**
   - Arquivo normal: `decrypt_data_single` ou `decrypt_data_streaming`
   - Volume oculto: Solicitação de token e escolha do volume

6. **Resultado**
   - Arquivo salvo com nome original
   - Confirmação de sucesso

### 4️⃣ Criptografar Múltiplos Arquivos

#### Fluxo de Operação
1. **Seleção**
   - Entrada de múltiplos caminhos de arquivo

2. **Compactação**
   - Criação de arquivo ZIP temporário

3. **Arquivo-chave (Opcional)**
   - Opção para aumentar a entropia

4. **Processo**
   - Escolha do método baseado no tamanho
   - Geração e cifragem de metadados

5. **Resultado**
   - ZIP criptografado salvo
   - Confirmação de sucesso

### 5️⃣ Gerar Token Efêmero

#### Fluxo de Operação
1. **Geração**
   - Token hexadecimal com 128 bits de entropia
   - Função `generate_ephemeral_token`

2. **Utilidade**
   - Acesso a volumes ocultos
   - Proteção da parte "real" dos dados

3. **Resultado**
   - Exibição do token para o usuário

### 6️⃣ Criar Volume Oculto

#### Fluxo de Operação
1. **Seleção de Arquivos**
   - Volume Falso: Dados "inocentes"
   - Volume Real: Dados confidenciais

2. **Configuração**
   - Senhas para cada volume
   - Arquivo-chave opcional
   - Parâmetros Argon2id

3. **Processo**
   - Criptografia individual via `encrypt_data_raw_chacha`
   - Concatenação com padding
   - Codificação Reed-Solomon

4. **Token**
   - Geração de token efêmero
   - Necessário para acesso futuro

5. **Metadados**
   - Cifragem das informações
   - Armazenamento em arquivo `.meta`

6. **Resultado**
   - Volume oculto criado
   - Token e instruções fornecidos

### 0️⃣ Sair

- Encerra a execução do programa de forma segura

## 🔄 Próximas Atualizações

- [ ] Interface gráfica moderna com Flet ✨
- [ ] Suporte a criptografia de diretórios completos
- [ ] Backup automático de metadados
- [ ] Integração com serviços de nuvem
- [ ] Suporte a chaves YubiKey
- [ ] Modo de operação em linha de comando
- [ ] Logs detalhados de operações 