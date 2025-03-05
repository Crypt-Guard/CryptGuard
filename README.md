# 🔐 CryptGuard

<div align="center">

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-audited-green.svg)](SECURITY.md)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

**CryptGuard é uma solução avançada de criptografia com interface moderna, focada em segurança e usabilidade.**

[🚀 Começar](#-início-rápido) •
[📖 Documentação](#-documentação) •
[🛡️ Segurança](#%EF%B8%8F-segurança) •
[🤝 Contribuir](#-contribuir) •
[📜 Licença](#-licença)

</div>

CryptGuard é uma solução avançada de criptografia com foco em segurança e usabilidade, agora reestruturada em uma arquitetura modular.

--------------------------------------------------------------------------------
## ✨ Características

- 🔒 **Criptografia Robusta**
  • Criptografia autenticada com ChaCha20Poly1305
  • Derivação de chaves com Argon2id
  • Correção de erros com Reed-Solomon

- 🎯 **Funcionalidades Avançadas**
  • Criptografia de textos e arquivos (single-shot)
  • Criptografia de arquivos grandes com modo streaming e chunk size dinâmico
  • Suporte a múltiplos arquivos (compactação em ZIP)
  • Criação de volumes ocultos com negação plausível
  • Key Rolling / Re-encryption: Troque a senha do volume real sem expor o volume falso

- Autenticação
  • [1] Senha + Arquivo-chave
  • [2] Somente Senha

- 💫 **Interface CLI**
  • Interface de linha de comando intuitiva
  • Feedback em tempo real durante operações de streaming

- 🛡️ **Segurança Aprimorada**
  • Verificação de força de senha com zxcvbn
  • Metadados criptografados (incluindo extensão original dos arquivos)
  • Gestão cuidadosa de memória sensível (zeroização de buffers)

--------------------------------------------------------------------------------
Estrutura do Projeto

A nova organização do repositório está organizada de forma modular na pasta "cryptguard/":

cryptguard/
├── __init__.py             -> Inicializa o pacote
├── config.py               -> Configurações globais (chunk size, thresholds, parâmetros Argon2, etc.)
├── password_utils.py       -> Funções para validação e coleta de senhas (Senha + Arquivo-chave ou Somente Senha)
├── argon_utils.py          -> Derivação de chaves com Argon2id
├── metadata.py             -> Criptografia e descriptografia de metadados (.meta)
├── rs_codec.py             -> Codificação e decodificação Reed-Solomon
├── chunk_crypto.py         -> Criptografia de chunks com ChaCha20Poly1305 + RS
├── single_shot.py          -> Criptografia/Descriptografia para arquivos pequenos (single-shot)
├── streaming.py            -> Criptografia/Descriptografia para arquivos grandes (streaming, com chunk size dinâmico)
├── hidden_volume.py        -> Funcionalidades de volumes ocultos e re-key do volume real
├── utils.py                -> Funções auxiliares (limpeza de tela, geração de nomes únicos, etc.)
└── main.py                 -> Interface de linha de comando principal

--------------------------------------------------------------------------------
### Pré-requisitos

- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)

### Instalação

1. Clone o repositório:
```bash
https://github.com/Crypt-Guard/CryptGuard.git
cd cryptguard
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

3. Execute o CryptGuard:
```bash
   python cryptguard/main.py
```
--------------------------------------------------------------------------------
## 💡 Guia de Uso

### Criptografar Arquivo
  - Criptografar Texto: Insira sua mensagem, a senha (com confirmação) e, opcionalmente, um arquivo-chave.
  - Criptografar Arquivo: Escolha o arquivo e siga as instruções. Para arquivos grandes, você pode definir um chunk size personalizado.

### Volumes Ocultos
  - Prepare dois conjuntos de arquivos: um para o volume falso e outro para o volume real.
  - Use senhas distintas para cada volume.
  - O sistema gera um token efêmero para acesso ao volume real.
  - Key Rolling / Re-encryption: Troque a senha do volume real sem alterar ou expor o volume falso.

### Descriptografar Arquivo
  - Selecione a opção para descriptografar e informe a senha correta. O arquivo será restaurado com sua extensão original (ex: .txt, .jpg, etc.).

--------------------------------------------------------------------------------
## 📖 Documentação

- [RoadMap](ROADMAP.md) - Funcionalidades e planos futuros
- [Segurança](SECURITY.md) - Guia de segurança e melhores práticas
- [Contribuição](CONTRIBUTING.md) - Como contribuir com o projeto
- [Licença](LICENSE) - Termos de licenciamento

--------------------------------------------------------------------------------
## 🛡️ Segurança

O CryptGuard foi projetado com foco em segurança, mas recomendamos:
  • Criptografia autenticada (ChaCha20Poly1305)
  • Derivação de chaves com Argon2id
  • Correção de erros com Reed-Solomon
  • Validação de força de senha (zxcvbn)
  • Gestão cuidadosa de memória sensível (zeroização de buffers)

Atenção: Realize auditorias de segurança e mantenha backups dos seus dados.
Consulte [SECURITY.md](SECURITY.md) para mais informações.

--------------------------------------------------------------------------------
## 🤝 Contribuir

Contribuições são bem-vindas! Por favor, leia nosso [Guia de Contribuição](CONTRIBUTING.md).

### Áreas de Contribuição

- 📝 Documentação
- 🐛 Correção de bugs
- ✨ Novas funcionalidades
- 🎨 Melhorias na interface
- 🌐 Traduções

## 📜 Licença

CryptGuard é licenciado sob a [Licença Apache 2.0](LICENSE).

--------------------------------------------------------------------------------

## 📊 Status do Projeto

  - Criptografia robusta: ✅
  - Documentação completa: ✅
  - Suporte a diretórios: 🚧
  - Integração com nuvem: 🚧
  - Suporte a dispositivos de autenticação física: 🚧

--------------------------------------------------------------------------------

## 🙏 Agradecimentos

Agradecemos à comunidade Python, aos desenvolvedores das bibliotecas utilizadas, e a todos os contribuidores deste projeto.

--------------------------------------------------------------------------------
<div align="center">

**CryptGuard** - Desenvolvido com ❤️

[⬆ Voltar ao topo](#-cryptguard)

</div>
