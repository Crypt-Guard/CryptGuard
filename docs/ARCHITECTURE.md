# Arquitetura

## Visão geral

O CryptGuard é uma aplicação Python com interface gráfica, serviços de criptografia e utilitários de linha de comando. A raiz do repositório contém documentação, governança e automação; a aplicação executável está integralmente em `CryptGuardv2/`.

Este documento é uma descrição de alto nível baseada na árvore, nos nomes dos módulos e na documentação existente. Ele não substitui revisão de código nem declara estabilidade das interfaces internas.

## Organização do repositório

- `CryptGuardv2/`: aplicação principal, dependências e módulos internos.
- `docs/`: documentação técnica e operacional.
- `more_info/`: contribuição, roadmap e material histórico.
- `.github/`: workflows, Dependabot e templates de colaboração.
- arquivos raiz: apresentação, segurança, licença, suporte e governança.

## Áreas conceituais da aplicação

### `crypto_core`

Concentra formatos criptográficos, KDF, AEAD/SecretStream, metadados, verificação de integridade, compatibilidade legada, escrita segura e mecanismos de hardening. É a área de maior sensibilidade: mudanças devem ser acompanhadas por análise do modelo de ameaça, compatibilidade e vetores de teste.

### `vault.py`

Fornece o Vault principal usado para organizar dados já criptografados e integra a persistência à interface. Migrações e compatibilidade de Vault devem ser tratadas como alterações de formato persistente.

### `modules/keyguard`

Agrupa geração de senhas, interface do KeyGuard e seu backend de Vault. O KeyGuard é integrado à janela principal, mas mantém responsabilidades próprias de armazenamento e desbloqueio.

### `containers`

Implementa containers seguros `.vault`, armazenamento atômico e a estrutura usada para transportar itens selecionados. O código de integração fica separado do formato de container.

### `cli`

Expõe comandos auxiliares para higiene de arquivos e gerenciamento de containers. Essas CLIs compartilham componentes da aplicação e não constituem atualmente uma API pública estável.

### `ui`

Contém fluxos gráficos complementares, incluindo configuração e integração de containers. A janela principal permanece em `main_app.py`.

### `integration`

Faz a ponte entre subsistemas, especialmente containers e Vaults. Essa camada reduz o acoplamento direto entre a interface e os formatos persistentes.

### `cg_platform`

Isola caminhos, ambiente Linux e efeitos específicos de Windows. Proteções dependentes de plataforma devem falhar de modo controlado quando indisponíveis.

## Fluxo conceitual

```text
GUI ou CLI
    -> validação e coordenação da operação
    -> Vault / KeyGuard / Containers, quando aplicável
    -> crypto_core para KDF, criptografia e autenticação
    -> safe I/O e adaptações de cg_platform
    -> arquivo persistido ou resultado verificado
```

Dados não devem ser considerados íntegros antes da validação criptográfica. A interface deve apresentar falhas sem transformar dados não autenticados em saída confiável.

## Limites arquiteturais

- A aplicação ainda concentra responsabilidades relevantes em módulos extensos.
- Interfaces internas e formatos precisam de testes de contrato antes de refatorações amplas.
- Hardening em Python e em sistemas operacionais distintos é necessariamente *best-effort*.
- Compatibilidade legada amplia a superfície de ataque e deve permanecer explicitamente testada.

Qualquer refatoração interna de `CryptGuardv2/` será realizada em uma etapa separada. A profissionalização documental deste repositório não altera a arquitetura executável atual.
