# Como contribuir com o CryptGuard

Contribuições devem ser revisáveis, reproduzíveis e compatíveis com o modelo de segurança do projeto. Ao participar, siga o [Código de Conduta](../CODE_OF_CONDUCT.md).

## Antes de abrir uma issue

Pesquise issues existentes e verifique a documentação. Não publique vulnerabilidades exploráveis: use o processo confidencial descrito em [SECURITY.md](../SECURITY.md).

Para relatar um bug, informe:

- versão ou commit analisado;
- sistema operacional e versão do Python;
- passos mínimos para reprodução;
- comportamento esperado e comportamento observado;
- logs sanitizados e arquivos de teste sem dados sensíveis.

Use o formulário de bug disponível no GitHub sempre que possível.

## Sugerindo uma funcionalidade

Explique o problema que a proposta resolve, os casos de uso e as alternativas consideradas. Inclua impactos de segurança, privacidade, compatibilidade de formato e manutenção. O [roadmap](ROADMAP.md) descreve prioridades, mas não impede novas propostas bem fundamentadas.

## Ambiente local

A aplicação está em `CryptGuardv2/`. A documentação atual adota Python 3.11 ou mais recente; o lock existente foi gerado com Python 3.13.

```bash
git clone https://github.com/Crypt-Guard/CryptGuard.git
cd CryptGuard/CryptGuardv2
python -m venv .venv
```

Ative o ambiente e instale as dependências:

```bash
# Linux/macOS
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

Não instale dependências a partir de `more_info/requirements.txt`; ele é apenas um resumo histórico.

## Branches e commits

Use nomes curtos no formato `<tipo>/<descrição>`, por exemplo:

- `fix/falha-verificacao-header`
- `feat/exportacao-manifesto`
- `docs/modelo-de-ameaca`
- `security/limite-kdf`
- `chore/atualiza-workflow`

Commits devem ser pequenos e explicar o resultado no imperativo. Prefixos como `fix:`, `feat:`, `docs:`, `test:` e `chore:` são recomendados. Evite misturar refatoração, mudança de comportamento e formatação no mesmo commit.

## Checks locais

Esta cópia do repositório não contém uma suíte automatizada de testes confirmada. Execute apenas os checks disponíveis e declare no pull request exatamente o que foi rodado.

```bash
# A partir da raiz do repositório; mantém bytecode fora da aplicação
PYTHONPYCACHEPREFIX=.cache/pycache python -m compileall CryptGuardv2

# Se as ferramentas estiverem instaladas
python -m ruff check CryptGuardv2
python -m bandit -r CryptGuardv2
```

No PowerShell, defina `$env:PYTHONPYCACHEPREFIX = ".cache/pycache"` antes do `compileall`. Se testes forem adicionados à contribuição, informe o comando e o resultado; não declare cobertura sem relatório verificável.

## Pull requests

1. Crie uma branch dedicada e mantenha o escopo pequeno.
2. Atualize ou adicione documentação relevante.
3. Execute os checks aplicáveis.
4. Preencha integralmente o [template de pull request](../.github/PULL_REQUEST_TEMPLATE.md).
5. Explique limitações conhecidas, migração e compatibilidade.

Mudanças em criptografia, formato de arquivo, KDF, Vault, KeyGuard, containers ou segurança devem incluir uma explicação explícita do impacto de segurança, ameaças afetadas, riscos de regressão, compatibilidade e vetores de teste. Não apresente um algoritmo próprio como seguro sem análise pública e evidências adequadas.

## Documentando mudanças de segurança

- Atualize `SECURITY.md` ou `docs/SECURITY_MODEL.md` quando o modelo de ameaça mudar.
- Registre mudanças visíveis em `CHANGELOG.md`.
- Documente alterações de formato e caminhos de migração.
- Use dados sintéticos em testes e exemplos.
- Mantenha detalhes exploráveis em canal privado até a correção coordenada.

## Licença

Ao contribuir, você concorda que sua contribuição seja distribuída sob a [Apache License 2.0](../LICENSE).
