# CryptGuard

[![Documentação](https://github.com/Crypt-Guard/CryptGuard/actions/workflows/docs.yml/badge.svg)](https://github.com/Crypt-Guard/CryptGuard/actions/workflows/docs.yml)
[![Checks Python](https://github.com/Crypt-Guard/CryptGuard/actions/workflows/python-static.yml/badge.svg)](https://github.com/Crypt-Guard/CryptGuard/actions/workflows/python-static.yml)
[![Licença Apache-2.0](https://img.shields.io/badge/licen%C3%A7a-Apache--2.0-blue.svg)](LICENSE)

CryptGuard é uma aplicação de criptografia autenticada de arquivos com interface gráfica em PySide6, CLI, Vault, KeyGuard e containers seguros.

> [!IMPORTANT]
> O projeto utiliza primitivas criptográficas consolidadas e práticas defensivas, mas nenhum software oferece segurança absoluta. Ele está em desenvolvimento, ainda precisa de testes automatizados mais amplos e não passou por auditoria criptográfica externa independente. Avalie o código e o modelo de ameaça antes de proteger dados críticos.

## Principais recursos

- Criptografia autenticada de arquivos.
- Verificação de integridade.
- Vault para organização de arquivos já criptografados.
- KeyGuard para geração e gerenciamento local de senhas.
- Containers seguros `.vault` para transporte e backup de itens selecionados.
- CLI para containers e higiene de arquivos.
- Hardening *best-effort* de memória, processo, arquivos temporários e logs.
- Secure delete *best-effort*, sujeito às limitações da mídia e do sistema de arquivos.

## Estado atual

A aplicação principal está em [`CryptGuardv2/`](CryptGuardv2/). A série 3.x documenta escrita no formato v5 com XChaCha20-Poly1305 SecretStream, Argon2id calibrado, cabeçalho associado à autenticação e metadados finais autenticados. A árvore também mantém componentes de compatibilidade para leitura de formatos anteriores.

Não há, neste repositório, uma release binária oficial ou uma garantia de estabilidade de formato e API. O uso atual deve ser feito a partir do código-fonte. Consulte o [changelog](CHANGELOG.md) e o [roadmap](more_info/ROADMAP.md) para distinguir o estado documentado das metas futuras.

A documentação externa, a governança e a automação do repositório estão organizadas fora da aplicação. A profissionalização do código interno de `CryptGuardv2/` será realizada separadamente, com testes e revisão próprios.

## Instalação pelo código-fonte

Use Python 3.11 ou mais recente. Python 3.13 é a versão usada para gerar o arquivo de dependências travadas atualmente disponível no projeto.

```bash
git clone https://github.com/Crypt-Guard/CryptGuard.git
cd CryptGuard/CryptGuardv2
python -m venv .venv
```

Ative o ambiente virtual:

```bash
# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

Instale e execute:

```bash
pip install -r requirements.txt
python main_app.py
```

Instruções específicas por plataforma estão em [Instalação](docs/INSTALLATION.md).

## Uso básico

Na interface gráfica, selecione um arquivo e use **Encrypt**, **Decrypt** ou **Verify** conforme a operação desejada. O Vault, o KeyGuard e os containers seguros possuem fluxos próprios na interface.

Para conhecer os comandos auxiliares e as práticas recomendadas, consulte o [guia de uso](docs/USAGE.md).

## Modelo de segurança

O CryptGuard busca oferecer confidencialidade e detecção de adulteração para dados armazenados, desde que a senha seja adequada e o ambiente de execução seja confiável. O formato v5 usa criptografia autenticada em streaming; parâmetros de derivação e metadados relevantes são vinculados à autenticação.

Vaults e containers reduzem a exposição operacional, mas não substituem controle de acesso do sistema, criptografia de disco ou backups. As proteções de memória, processo e exclusão segura são *best-effort*.

Leia a [Política de Segurança](SECURITY.md) e o [modelo de segurança completo](docs/SECURITY_MODEL.md) antes de usar o projeto com dados sensíveis.

## Limitações

- Uma máquina comprometida, malware, keylogger ou acesso root/administrador pode capturar senhas e dados em texto claro.
- Exclusão segura não pode ser garantida em SSDs, NVMe, sistemas com *copy-on-write*, snapshots ou backups.
- Senhas perdidas não podem ser recuperadas pelo projeto.
- Arquivos autenticados corrompidos não devem ser reparados manualmente; restaure uma cópia íntegra.
- Não há promessa de segurança absoluta, inviolabilidade ou adequação automática a requisitos regulatórios.
- Compatibilidade legada deve ser validada com cópias de teste antes de qualquer migração importante.

## Documentação

- [Arquitetura](docs/ARCHITECTURE.md)
- [Modelo de segurança](docs/SECURITY_MODEL.md)
- [Instalação](docs/INSTALLATION.md)
- [Uso](docs/USAGE.md)
- [Dependências](docs/DEPENDENCIES.md)
- [Processo de release](docs/RELEASE_PROCESS.md)
- [Política de segurança](SECURITY.md)
- [Guia de contribuição](more_info/CONTRIBUTING.md)
- [Roadmap](more_info/ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Suporte](SUPPORT.md)
- [Governança](GOVERNANCE.md)

## Contribuindo

Issues e pull requests são bem-vindos. Antes de contribuir, leia o [guia de contribuição](more_info/CONTRIBUTING.md) e o [Código de Conduta](CODE_OF_CONDUCT.md). Mudanças em criptografia, formato de arquivo, KDF, Vault ou controles de segurança devem explicar impacto, riscos e compatibilidade.

## Política de segurança

Não publique vulnerabilidades exploráveis em issues. Siga o processo de divulgação responsável descrito em [SECURITY.md](SECURITY.md).

## Licença

CryptGuard é distribuído sob a [Apache License 2.0](LICENSE). Dependências de terceiros mantêm suas próprias licenças; consulte também o arquivo [NOTICE](NOTICE).
