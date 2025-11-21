# 🛡️ Security Policy - CryptGuard v3.x

CryptGuard entrega criptografia forte e autenticada para arquivos, Vaults e containers, mas nenhum software oferece seguranca absoluta. Este documento explica o que e protegido, o que nao e, e como relatar vulnerabilidades.

---

## 🎯 Scope & threat model
- **In scope (v3.x)**  
  - Formato v5 `.cg2`, Vault do CryptGuard, Vault do KeyGuard e containers `.vault`.  
  - Atacantes offline sem a senha.  
  - Detecao de corrupcao/adulteracao em cabecalho, quadros de streaming ou lixo anexado (falha de autenticacao limpa).
- **Out of scope**  
  - Maquinas comprometidas (malware, keylogger), hipervisor/OS malicioso, acesso root/admin.  
  - Snapshots/backups do SO que capturam plaintext.  
  - Vazamentos causados por ferramentas externas.  
  - Nao existem hidden volumes ou decoy volumes na linha 3.x (qualquer referencia a isso e legado 1.x).

---

## 🔐 Cryptographic design & guarantees
- XChaCha20-Poly1305 via libsodium SecretStream; TAG_FINAL autentica fechamento e metadados.  
- Argon2id com perfis **Interactive** (responsivo) e **Sensitive** (custo maior por tentativa); parametros calibrados por maquina e autenticados no cabecalho.  
- Metadados privados (nome, extensao, tamanho real) cifrados/autenticados; Vault e containers armazenam apenas payload cifrado.  
- Formatos:  
  - `.cg2` (v5) sempre escrito com SecretStream; leitor aceita formatos anteriores.  
  - Vault: guarda apenas arquivos cifrados, cabecalho vinculado como AAD.  
  - `.vault`: containers com Argon2id + SecretStream em TLV (`cg_file`, `kg_secret`, `manifest`).  

---

## 🧱 Hardening & best-effort protections
- **Memoria e segredos:** secure memory via libsodium, `SecureBytes`, comparacoes em tempo constante (`secretcmp`), limpeza explicita de buffers, mascaramento de logs/variaveis (`secretenv`, obfuscadores).  
- **Processo:** tentativas de bloquear core dump/ptrace em POSIX e ajustes de DEP/error-mode em Windows; falhas geram `SecurityWarning` mas nao interrompem o app.  
- **Higiene de arquivos:** `cli/hygiene_cli.py` e `crypto_core/file_hygiene.py` para limpar temporarios e remocao segura best effort. Em SSD/NVMe, wear-leveling pode manter blocos antigos; combine com criptografia de disco completa para garantias fortes.  

---

## ✅ Safe usage guidelines
1) Use senhas fortes e unicas; prefira o perfil Sensitive quando possivel.  
2) Mantenha backups separados de `.cg2`, Vault do CryptGuard, Vault do KeyGuard e containers `.vault`; perda de arquivo + senha = perda permanente.  
3) Verifique integridade com **Verify** antes de abrir arquivos suspeitos; nao tente reparar dados autenticados corrompidos.  
4) Proteja o ambiente: SO e libs atualizados, evite rodar em maquinas nao confiaveis, nao execute como admin sem necessidade.  
5) Compartilhe containers com a senha enviada por canal separado e seguro.  

---

## 🚨 Reporting a vulnerability
- Nao abra issue publica para assuntos de seguranca.  
- Contato preferencial: `cryptguard737@gmail.com`.  
- Inclua descricao clara, impacto esperado, passos de reproducao e (quando possivel) provas de conceito ou vetores de teste.  
- O time reconhece o recebimento, investiga e publica correcoes; avisos publicos sao feitos quando apropriado (releases/notas de seguranca).  

---

## ⚖️ Legal & export
- Software fornecido "no estado em que se encontra", sem garantias expressas ou implicitas.  
- O usuario e responsavel por escolher senhas, perfis de KDF e politica de backup adequados ao seu modelo de ameaca.  
- O uso deve obedecer leis locais de criptografia/exportacao (binarios podem se enquadrar em ECCN 5D002 / License Exception ENC).  
