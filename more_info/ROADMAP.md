# Roadmap do CryptGuard 3.x

Este documento apresenta intenções de evolução, não promessas de entrega. Prioridades podem mudar após testes, revisão de segurança e disponibilidade dos mantenedores.

## Estado atual

- Aplicação principal concentrada em `CryptGuardv2/`.
- Writer documentado no formato v5 com SecretStream e Argon2id.
- GUI em PySide6, Vault, KeyGuard, containers `.vault` e CLIs auxiliares.
- Documentação, templates comunitários e CI inicial para existência de documentos, compilação Python e análises não bloqueantes.
- Projeto em desenvolvimento, sem auditoria criptográfica externa independente confirmada.

## Curto prazo

- Construir uma suíte automatizada reproduzível para criptografia, autenticação, corrupção, senhas incorretas e compatibilidade.
- Estabelecer testes de integração para Vault, KeyGuard, containers e CLIs.
- Corrigir gradualmente achados de Ruff e Bandit até tornar esses checks bloqueantes.
- Definir ambientes suportados de Python e sistemas operacionais com evidências de CI.
- Revisar e documentar formatos persistentes e estratégias de migração.

## Médio prazo

- Separar dependências de runtime, GUI, testes e qualidade.
- Unificar a estratégia entre `requirements.txt` e `requirements.lock.txt` sem perder reprodutibilidade.
- Criar empacotamento reproduzível e validar instaladores em ambientes isolados.
- Formalizar CI/CD para artefatos, matrizes de plataforma e testes de regressão.
- Produzir documentação bilíngue, mantendo português brasileiro como fonte inicial durante a transição.
- Adotar processo de release, notas e política de compatibilidade verificáveis.

## Longo prazo

- Contratar ou coordenar auditoria criptográfica externa independente.
- Publicar releases assinadas e material verificável de procedência dos artefatos.
- Evoluir defesa de memória, processo e armazenamento com testes específicos por plataforma.
- Avaliar integrações avançadas somente após estabilização do formato, testes e modelo de ameaça.

## Itens removidos ou legados

- Hidden volumes e decoy volumes não fazem parte da série 3.x e não devem ser anunciados como recurso disponível.
- Formatos, algoritmos e perfis da série 2.x permanecem apenas como contexto histórico ou compatibilidade de leitura quando implementada.
- Metas antigas como FIPS, PKCS#11, plugins ou atualizador automático não são compromissos ativos; exigem nova proposta, análise de segurança e manutenção sustentável.
- Alegações antigas de testes completos ou builds multiplataforma não devem ser reproduzidas sem automação e artefatos verificáveis.
