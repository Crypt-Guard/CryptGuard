# Governança

## Objetivo

A governança do CryptGuard busca tornar decisões técnicas verificáveis, preservar a segurança dos usuários e manter um processo de contribuição aberto.

## Responsabilidades

Os mantenedores do repositório são responsáveis por triagem, revisão, integração de mudanças, política de segurança e preparação de releases. Contribuidores podem propor alterações por issues e pull requests, mas acesso de escrita não é requisito para participar das decisões.

## Tomada de decisão

Decisões rotineiras podem ser resolvidas na revisão do pull request. Mudanças amplas devem registrar motivação, alternativas, compatibilidade e riscos para permitir discussão antes da integração.

Alterações em criptografia, formato de arquivo, KDF, Vault, KeyGuard, containers ou controles de segurança exigem:

- descrição explícita do modelo de ameaça afetado;
- análise de compatibilidade e migração;
- vetores de teste ou método reproduzível de validação;
- revisão por mantenedor com contexto suficiente para avaliar o risco.

Na ausência de consenso, prevalece a alternativa mais conservadora para compatibilidade e segurança, ou a mudança permanece pendente até que existam evidências suficientes.

## Releases e segurança

Somente mantenedores autorizados podem publicar releases. O processo futuro deve seguir [docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md). Vulnerabilidades são tratadas de acordo com [SECURITY.md](SECURITY.md), fora de discussões públicas até que a divulgação seja segura.

## Alterações desta governança

Mudanças neste documento devem ser propostas por pull request, com justificativa e período razoável para revisão comunitária.
