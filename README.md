# 🔐 CryptGuard v3.0 (final hardening release)

**CryptGuard** e um app de criptografia de arquivos com GUI em PySide6 e CLIs essenciais. A serie 3.0 escreve sempre o formato v5 usando XChaCha20-Poly1305 SecretStream, Argon2id calibrado e suporte integrado a Vault, KeyGuard e containers seguros (.vault) para compartilhamento/backup.

---

## ✨ Highlights (v3.0)

| # | Feature | What it does |
|---|---------|--------------|
| 1 | XChaCha20-Poly1305 (SecretStream) | Criptografia autenticada em streaming com marcador final autenticado. |
| 2 | Header como AAD | Cabecalho + parametros de KDF vinculados; qualquer alteracao quebra a autenticacao. |
| 3 | Metadados finais autenticados | TAG_FINAL inclui nome/extensao, tamanho real, padding e contagem de blocos. |
| 4 | Argon2id calibrado (Interactive/Sensitive) | Perfis com custo ajustado na maquina, gravados no cabecalho autenticado. |
| 5 | Padding opcional 0/4/8/16 KiB | Camufla tamanho sem perder verificacao do tamanho real. |
| 6 | Verify robusto | Corrupcao em cabecalho/quadros/dados anexados falha com erro limpo. |
| 7 | Vault + KeyGuard integrados | Armazenamento de .cg2 e gerador/gerenciador de senhas com vault dedicado. |
| 8 | Containers seguros (.vault) | Transporta selecoes do Vault do CryptGuard e do KeyGuard em um unico arquivo. |
| 9 | CLIs de higiene e containers | Limpeza/remocao segura de temporarios e automacao de containers via CLI. |
| 10 | Hardening best effort | secure memory libsodium, protecoes de processo, logs com mascaramento. |

---

## 🆕 O que mudou na serie 3.0

**Core/Format**
- ✅ Escrita unica no formato v5 (.cg2) com SecretStream; leitor continua compativel com formatos antigos.
- ✅ Metadados finais autenticados (`orig_name`, `orig_ext`, `pt_size`, `chunks`, `pad`) em TAG_FINAL.
- ✅ Padding maximo 16 KiB para equilibrar privacidade de tamanho e overhead.

**KDF & Perfis**
- 🔐 Argon2id com calibracao por maquina; perfis **Interactive** (responsivo) e **Sensitive** (custo maior por tentativa).
- 🔧 Parametros (tempo, memoria, paralelismo, perfil) ficam autenticados no cabecalho.

**Vault**
- 📦 Armazena apenas arquivos ja cifrados (.cg2) com cabecalho vinculado como AAD; IO busca ser atomico e logs mascaram dados sensiveis.

**KeyGuard**
- 🔑 Gerador de senhas com modulo `secrets`, estimativa de entropia, conjuntos de caracteres e vault proprio com rate-limit de desbloqueio.

**Containers seguros**
- 🧳 Formato `.vault` com Argon2id e SecretStream em TLV (`cg_file`, `kg_secret`, `manifest`) para compartilhar/backup com selecao guiada ou via CLI.

**Compatibilidade e limpeza**
- ♻️ Leitura de formatos antigos preservada; escrita sempre v5.
- 🧹 CLIs de higiene para limpar temporarios e remocao segura best effort.

---

## 🔧 Como funciona (visao rapida do formato v5)
- Cabecalho do SecretStream + JSON de KDF sao autenticados como AAD (commitment cabecalho/payload).
- Fluxo em quadros autenticados; cada quadro valida antes de liberar bytes.
- TAG_FINAL carrega JSON autenticado com nome/extensao, tamanho real e padding aplicado.
- Padding opcional (0/4/8/16 KiB) apenas no ultimo bloco; o tamanho real e validado.
- Apenas XChaCha20-Poly1305 SecretStream e usado para escrita; leituras aceitam legado.

---

## 🧪 Security model (notas rapidas)
- AEAD: XChaCha20-Poly1305 via libsodium SecretStream; final autenticado protege fechamento e metadados.
- KDF: Argon2id com perfis Interactive/Sensitive e parametros calibrados p/ maquina, autenticados no cabecalho.
- Metadados privados: nome, extensao e tamanho ficam cifrados/autenticados; Vault/containers so guardam payloads cifrados.
- Hardening best effort: secure memory, comparacoes em tempo constante, protecoes de processo (POSIX/Windows), mascaramento de logs.
- Fora do escopo: maquina comprometida, keylogger, hipervisor malicioso, snapshots/backup do SO capturando plaintext.

---

## 📦 Instalacao

### Windows (binario)
1) Baixe o instalador ou `.exe` na pagina de Releases.  
2) Execute sem privilegios de administrador.  
> 💡 Tip: rodar como admin pode bloquear drag-and-drop (UAC).

### Codigo-fonte (Python 3.11+)
```bash
git clone https://github.com/Crypt-Guard/CryptGuard.git
cd CryptGuard/CryptGuardv2

python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
python main_app.py
```

---

## 🖥️ Usando o app (GUI)
1) Arraste ou selecione um arquivo.  
2) Escolha o perfil KDF (Interactive/Sensitive) e, se quiser, padding e data de expiracao.  
3) Opcional: marcar para colocar o `.cg2` no Vault.  
4) Digite uma senha forte e clique **Encrypt**. Para abrir um `.cg2`, selecione e use **Decrypt**.  
5) Use **Verify** para checar integridade sem gravar plaintext.  

---

## 🔑 KeyGuard Password Generator
**Core Features**
- Geracao criptograficamente segura (modulo `secrets`), estimativa de entropia e filtros de padrao fraco.
- Conjuntos de caracteres: digitos, letras, alfanumerico, ASCII imprimivel; comprimento flexivel.

**KeyGuard Vault**
- Vault dedicado para senhas/segredos, com compressao e gravacao atomica onde possivel.
- Desbloqueio possui rate-limit para dificultar tentativas rapidas.

**Integracao**
- Sidebar integrada ao app; pode acompanhar fluxos de Vault e containers seguros (.vault).

**Usage Tips**
- Prefira senhas longas/aleatorias; nao reutilize senhas de containers.
- Se notar espacos acidentais em inicio/fim, corrija antes de salvar ou usar.

---

## ⚙️ Tuning & options
- **KDF profile**: Interactive (responsivo) vs Sensitive (custo maior por tentativa).  
- **Pad size**: 0 / 4 / 8 / 16 KiB; mais padding = mais camuflagem, mais overhead.  
- **Expiration**: metadado autenticado (nao-secreto) para sinalizar validade/retencao.  

---

## 🧳 Secure Containers (.vault)
- GUI: em **Settings > Secure Containers**, um wizard de 3 passos permite escolher itens do Vault do CryptGuard e do KeyGuard para criar o `.vault`. Ao importar, escolha integrar nos vaults ou exportar arquivos.
- CLI: `python -m cli.container_cli --help` para listar, extrair, integrar ou criar containers em scripts/batch.
- Formato: Argon2id + SecretStream em TLV (`cg_file`, `kg_secret`, `manifest`); cabecalho autenticado como AAD.

---

## 🛠️ Linha de comando
```bash
# Higiene / remocao segura (best effort)
python -m cli.hygiene_cli --status
python -m cli.hygiene_cli --temp
python -m cli.hygiene_cli --file PATH [--passes N]

# Containers seguros
python -m cli.container_cli list --in backup.vault
python -m cli.container_cli extract --in backup.vault --to ./destino
python -m cli.container_cli create --out novo.vault --kdf-profile strong
```

---

## 🔍 Troubleshooting
- ❌ **InvalidTag / autenticacao falhou**: o arquivo foi alterado (cabecalho, quadros ou lixo anexo). Nao tente reparar dados autenticados; recupere de backup.
- 🖱️ **Drag-and-drop no Windows**: nao rode como admin; o UAC pode bloquear origem nao elevada.
- 🔎 **KeyGuard nao aparece**: verifique se o modulo `modules/keyguard/` esta presente/importavel.
- 🗄️ **Vault corrompido ou com senha errada**: sem senha correta nao ha recuperacao; use backups.
- 🔒 **Secure delete pouco efetivo em SSD/NVMe**: limitacao estrutural; combine com criptografia de disco completa.

---

## 🧠 Tips
- Use senhas longas/aleatorias; prefira o perfil Sensitive quando o hardware permitir.
- Mantenha backups separados para `.cg2`, Vault do CryptGuard, Vault do KeyGuard e containers `.vault`.
- Evite rodar em maquinas potencialmente comprometidas; mantenha SO e libs atualizados.
- Compartilhe a senha de containers por canal separado e seguro.

---

## 🤝 Contributing
- Pull Requests bem-vindos (testes adicionais, empacotamento, UX). Documente qualquer mudanca que afete seguranca.
- Para vulnerabilidades, use o contato confidencial em `SECURITY.md` (nao abra issue publica).

## 📜 License
- Apache-2.0. Veja `LICENSE`.

## 🛡️ Security Policy
- Consulte `SECURITY.md` para ameaca, limites e fluxo de reporte.

## 📚 Changelog (summary)
- **3.0**: Escrita unica SecretStream, AAD no cabecalho, TAG_FINAL com metadados autenticados, padding ate 16 KiB, Argon2id calibrado com perfis, Vault/KeyGuard integrados, containers .vault, CLIs de higiene/containers, hardening adicional.
- **2.7.x e anteriores**: modos multi-algoritmo, footer END0/NAM0, padding ate 1 MiB, primeiros conceitos de hidden volume (removidos), Vault legado.

## 🌍 Export Compliance
- Conteudo criptografico de codigo aberto com algoritmos padronizados (AES-GCM, XChaCha20-Poly1305, etc.). Binarios podem estar sujeitos a ECCN 5D002 / License Exception ENC; use conforme as leis locais e de sancoes.

## 🙏 Acknowledgements / Third-party
- cryptography, argon2-cffi, PyNaCl/libsodium, reedsolo, PySide6/Qt, ttkbootstrap, QtAwesome, zxcvbn-python.
