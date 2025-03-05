🔐 CryptGuard

[License: Apache 2.0]   [Python: 3.8+]   [Security: audited]   [Contributions Welcome]

CryptGuard é uma solução avançada de criptografia com foco em segurança e usabilidade, agora reestruturada em uma arquitetura modular.

--------------------------------------------------------------------------------
Características

- Criptografia Robusta
  • Criptografia autenticada com ChaCha20Poly1305
  • Derivação de chaves com Argon2id
  • Correção de erros com Reed-Solomon

- Funcionalidades Avançadas
  • Criptografia de textos e arquivos (single-shot)
  • Criptografia de arquivos grandes com modo streaming e chunk size dinâmico
  • Suporte a múltiplos arquivos (compactação em ZIP)
  • Criação de volumes ocultos com negação plausível
  • Key Rolling / Re-encryption: Troque a senha do volume real sem expor o volume falso

- Autenticação
  • [1] Senha + Arquivo-chave
  • [2] Somente Senha

- Interface CLI
  • Interface de linha de comando intuitiva
  • Feedback em tempo real durante operações de streaming

- Segurança Aprimorada
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
Início Rápido

Pré-requisitos:
  - Python 3.8 ou superior
  - pip

Instalação:
1. Clone o repositório:
   git clone https://github.com/Crypt-Guard/CryptGuard.git
   cd CryptGuard

2. Instale as dependências:
   pip install -r requirements.txt

3. Execute o CryptGuard:
   python cryptguard/main.py

--------------------------------------------------------------------------------
Guia de Uso

Criptografar Texto e Arquivos:
  - Criptografar Texto: Insira sua mensagem, a senha (com confirmação) e, opcionalmente, um arquivo-chave.
  - Criptografar Arquivo: Escolha o arquivo e siga as instruções. Para arquivos grandes, você pode definir um chunk size personalizado.

Volumes Ocultos:
  - Prepare dois conjuntos de arquivos: um para o volume falso e outro para o volume real.
  - Use senhas distintas para cada volume.
  - O sistema gera um token efêmero para acesso ao volume real.
  - Key Rolling / Re-encryption: Troque a senha do volume real sem alterar ou expor o volume falso.

Descriptografar Arquivos:
  - Selecione a opção para descriptografar e informe a senha correta. O arquivo será restaurado com sua extensão original (ex: .txt, .jpg, etc.).

--------------------------------------------------------------------------------
Documentação

- RoadMap – Funcionalidades e planos futuros.
- Segurança – Guia de melhores práticas e auditoria.
- Contribuição – Como contribuir para o projeto.
- Licença – Termos de uso e licenciamento.

--------------------------------------------------------------------------------
Segurança

CryptGuard foi desenvolvido com foco em segurança, adotando:
  • Criptografia autenticada (ChaCha20Poly1305)
  • Derivação de chaves com Argon2id
  • Correção de erros com Reed-Solomon
  • Validação de força de senha (zxcvbn)
  • Gestão cuidadosa de memória sensível (zeroização de buffers)

Atenção: Realize auditorias de segurança e mantenha backups dos seus dados.

--------------------------------------------------------------------------------
Contribuir

Contribuições são bem-vindas! Consulte o Guia de Contribuição para mais detalhes.

Áreas de Contribuição:
  • Documentação
  • Correção de bugs
  • Novas funcionalidades
  • Melhorias na interface
  • Testes e segurança

--------------------------------------------------------------------------------
Licença

CryptGuard é licenciado sob a Licença Apache 2.0.

--------------------------------------------------------------------------------
Status do Projeto

  - Criptografia robusta: ✅
  - Documentação completa: ✅
  - Suporte a diretórios: 🚧
  - Integração com nuvem: 🚧
  - Suporte a dispositivos de autenticação física: 🚧

--------------------------------------------------------------------------------
Agradecimentos

Agradecemos à comunidade Python, aos desenvolvedores das bibliotecas utilizadas, e a todos os contribuidores deste projeto.

--------------------------------------------------------------------------------
CryptGuard – Desenvolvido com ❤️ pela comunidade

[⬆ Voltar ao topo]
