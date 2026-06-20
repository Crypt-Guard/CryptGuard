# Changelog

Todas as mudanças relevantes do projeto serão documentadas neste arquivo.

O formato segue os princípios do [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto pretende adotar [Versionamento Semântico](https://semver.org/lang/pt-BR/) para releases futuras. O histórico inicial abaixo foi reconstruído a partir da documentação existente; ele não representa uma lista verificada de tags, datas ou commits publicados.

## [Unreleased]

### Adicionado

- Documentação de arquitetura, instalação, uso, dependências e modelo de segurança.
- Metadados comunitários, templates do GitHub e automações iniciais de documentação, análise estática e segurança.

### Alterado

- README, política de segurança, guia de contribuição e roadmap profissionalizados para a série 3.x.

## [3.0.0] - A definir

### Documentado

- Escrita única no formato v5 para novos arquivos.
- XChaCha20-Poly1305 SecretStream para criptografia autenticada em streaming.
- Cabeçalho e parâmetros da KDF associados como AAD.
- `TAG_FINAL` com metadados autenticados.
- Padding configurável de até 16 KiB.
- Argon2id calibrado para derivação de chaves.
- Integração entre Vault e KeyGuard.
- Containers seguros com extensão `.vault`.
- CLIs para higiene de arquivos e gerenciamento de containers.
- Hardening adicional de memória, processo, temporários e logs em regime *best-effort*.

> Esta seção descreve o estado documentado da série 3.x. Não declara que uma release oficial 3.0.0 tenha sido publicada.

## [2.x] - Legado

- Histórico reconstruído a partir da documentação anterior.
- Incluía formatos e combinações criptográficas anteriores ao writer v5.
- Referências a hidden volumes ou decoy volumes são legadas e não fazem parte da linha 3.x.
- Datas, commits e números intermediários não foram incluídos por falta de histórico verificável nesta cópia do repositório.
