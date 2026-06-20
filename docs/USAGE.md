# Uso

## Antes de começar

- Trabalhe em uma máquina confiável e atualizada.
- Mantenha backup do arquivo original até validar o resultado criptografado.
- Use senhas longas, únicas e preferencialmente geradas pelo KeyGuard ou por outro gerenciador confiável.
- Não use dados críticos como primeiro teste de uma nova versão.

Inicie a interface a partir da pasta `CryptGuardv2/`:

```bash
python main_app.py
```

## Encrypt

1. Selecione ou arraste o arquivo de entrada.
2. Escolha as opções disponíveis de perfil KDF e padding.
3. Informe e confirme uma senha forte.
4. Use **Encrypt** e aguarde a conclusão.
5. Preserve o original até verificar que o `.cg2` pode ser autenticado e descriptografado em uma cópia de teste.

Não reutilize a senha de login, do Vault ou de um container.

## Decrypt

1. Selecione o arquivo `.cg2`.
2. Escolha **Decrypt** e informe a senha correta.
3. Confira cuidadosamente o destino antes de gravar o texto claro.
4. Trate falhas de autenticação como senha incorreta, corrupção ou adulteração; não tente corrigir bytes manualmente.

O arquivo descriptografado deixa de ter a proteção do CryptGuard. Proteja o diretório de destino e remova cópias temporárias quando não forem mais necessárias.

## Verify

Use **Verify** para solicitar a verificação de integridade de um `.cg2`. Uma verificação válida indica que as regiões autenticadas foram aceitas pela implementação e pela senha fornecida; não atesta que o arquivo original era seguro, confiável ou livre de malware.

## Vault

O Vault principal organiza arquivos já criptografados. Use uma senha exclusiva, mantenha backup do Vault e valide a restauração. Um Vault aberto expõe seus itens ao ambiente em execução e não substitui permissões do sistema ou criptografia de disco.

## KeyGuard

O painel KeyGuard gera senhas e oferece um Vault dedicado. Prefira comprimentos altos e conjuntos de caracteres adequados ao sistema de destino. Antes de fechar o painel, confirme que a senha foi copiada ou armazenada no local pretendido.

Perder a senha mestra do KeyGuard pode tornar seu conteúdo irrecuperável.

## Containers seguros

Containers `.vault` transportam seleções do Vault principal e do KeyGuard. Use senha exclusiva, mantenha cópia de segurança e compartilhe a senha por canal separado. Ao importar, confira conflitos e destino antes de substituir itens.

## Linha de comando

Execute os comandos a partir de `CryptGuardv2/` e consulte a ajuda disponível:

```bash
python -m cli.hygiene_cli --help
python -m cli.container_cli --help
```

Exemplos de higiene:

```bash
python -m cli.hygiene_cli --status
python -m cli.hygiene_cli --temp --dry-run
python -m cli.hygiene_cli --file CAMINHO --passes 3 --dry-run
```

Remova `--dry-run` somente depois de revisar o destino. Sobrescrita não garante exclusão física em SSD/NVMe.

Exemplos de containers:

```bash
python -m cli.container_cli list --in backup.vault
python -m cli.container_cli extract --in backup.vault --to ./destino
python -m cli.container_cli create --out novo.vault --kdf-profile strong
```

Use `--help` em cada subcomando para conferir opções e comportamento da versão em execução.

## Backups e limitações

- Mantenha mais de uma cópia, preferencialmente em mídias e locais distintos.
- Teste periodicamente a leitura das cópias sem substituir os originais.
- Faça backup dos arquivos criptografados, Vaults, containers e informações necessárias para identificar suas senhas.
- Não armazene senha e artefato protegido no mesmo canal sem proteção adicional.
- Consulte o [Modelo de Segurança](SECURITY_MODEL.md) e a [Política de Segurança](../SECURITY.md).
