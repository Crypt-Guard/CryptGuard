# Instalação

## Estado de distribuição

O CryptGuard deve ser executado a partir do código-fonte. Esta documentação não presume a existência de instaladores ou binários oficiais.

## Requisitos

- Python 3.11 ou mais recente.
- `pip` e suporte a ambientes virtuais.
- Espaço adicional para PySide6/Qt e demais dependências nativas.
- Ambiente gráfico para executar `main_app.py`.

O arquivo `requirements.lock.txt` atual foi gerado com Python 3.13. Para desenvolvimento reproduzível, Python 3.13 é a referência mais próxima do lock; outras versões suportadas devem ser verificadas no ambiente de destino.

## Instalação padrão

```bash
git clone https://github.com/Crypt-Guard/CryptGuard.git
cd CryptGuard
cd CryptGuardv2
python -m venv .venv
```

Ative o ambiente virtual.

Linux ou macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Instale as dependências e inicie o aplicativo:

```bash
pip install -r requirements.txt
python main_app.py
```

Use `requirements.txt` para a instalação operacional atual. O lock pode ser usado somente quando o ambiente for compatível e houver necessidade de reproduzir exatamente as versões registradas:

```bash
pip install -r requirements.lock.txt
```

## Windows

- Use uma instalação oficial de Python com `pip` e `venv`.
- Se o PowerShell bloquear a ativação, consulte a política de execução da sua organização; não desabilite controles de segurança sem entender o impacto.
- Execute sem privilégios administrativos, salvo necessidade específica e revisada.
- Drag-and-drop entre processos com níveis de privilégio diferentes pode ser bloqueado pelo Windows.

## Linux

- Prefira os pacotes de Python da distribuição ou uma instalação gerenciada pelo usuário.
- PySide6 pode depender de bibliotecas gráficas do sistema para X11 ou Wayland; os nomes dos pacotes variam por distribuição.
- Não execute a GUI como root.

## macOS

- Use um Python que forneça `venv` e seja compatível com as wheels das dependências.
- O Gatekeeper pode alertar sobre código baixado ou não assinado. Como não há bundle oficial documentado, execute o código somente após revisar sua procedência.

## Atualização

Antes de atualizar, faça backup dos arquivos `.cg2`, Vaults e containers. Crie um ambiente virtual novo, instale as dependências e valide cópias de teste antes de usar dados importantes. Não presuma compatibilidade apenas pelo número da versão.

## Problemas comuns

- **Falha ao instalar uma wheel:** confirme versão e arquitetura do Python e disponibilidade para o sistema.
- **Qt não inicia:** verifique sessão gráfica, drivers e bibliotecas de plataforma.
- **ImportError:** confirme que o ambiente virtual correto está ativo e que a instalação terminou sem erros.
- **Arquivo não abre:** preserve o original, verifique a senha e consulte [Suporte](../SUPPORT.md).
