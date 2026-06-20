# Dependências

## Fonte operacional

A lista operacional está em `CryptGuardv2/requirements.txt`. O arquivo `more_info/requirements.txt` é apenas um resumo histórico e não deve orientar instalações.

## Segurança e criptografia

- `cryptography`: primitivas criptográficas auxiliares e derivação de material.
- `argon2-cffi` e bindings: Argon2id para derivação baseada em senha.
- `PyNaCl`/libsodium: SecretStream, SecretBox e recursos de memória segura expostos pela biblioteca.
- `cffi`: integração com componentes nativos.
- `reedsolo`: suporte de codificação de redundância usado por áreas legadas ou auxiliares.
- `zxcvbn`: estimativa heurística de força de senha.

Uma estimativa de senha não substitui uma KDF adequada nem garante resistência real.

## Interface gráfica

- `PySide6`, `pyside6-essentials`, `pyside6-addons` e `shiboken6`: Qt for Python.
- `QtAwesome`: ícones para componentes Qt.
- `ttkbootstrap` e `Pillow`: temas e imagens usados por componentes de interface.

## Runtime e sistema

- `psutil`: informações e operações relacionadas ao processo e ao sistema.

Algumas dependências carregam bibliotecas nativas. Compatibilidade depende do Python, arquitetura e sistema operacional.

## Teste e qualidade

O manifesto atual também inclui:

- `pytest`, `pytest-cov` e `hypothesis` para testes;
- `ruff` para lint e análise estática;
- `mypy` para tipagem estática;
- `bandit` para análise de padrões de segurança.

A presença dessas ferramentas no manifesto não comprova existência, cobertura ou aprovação de uma suíte de testes.

## `requirements.txt` e `requirements.lock.txt`

- `requirements.txt` declara dependências diretas com limites mínimos e é o ponto de instalação atual.
- `requirements.lock.txt` registra versões diretas e transitivas exatas; o cabeçalho informa geração com Python 3.13.

Como os mínimos e o lock podem divergir ao longo do tempo, atualizações devem ser testadas juntas. O lock não garante, sozinho, reprodutibilidade entre sistemas com wheels ou bibliotecas nativas diferentes.

Uma profissionalização futura deve separar runtime, GUI e ferramentas de desenvolvimento, definir uma única política de lock e automatizar sua verificação. Essa unificação não é feita agora porque os manifestos operacionais estão dentro de `CryptGuardv2/` e exigem revisão separada.

## Licenças e atualizações

Consulte as licenças e advisories nos projetos de origem. O arquivo [NOTICE](../NOTICE) fornece apenas uma visão de alto nível e não substitui os avisos exigidos pelas versões efetivamente distribuídas.
