# Processo de Release

Este documento define um processo futuro. Ele não cria nem afirma a existência de uma release oficial.

## Versionamento

Adotar Versionamento Semântico após definir claramente a superfície pública e os formatos persistentes:

- **MAJOR:** incompatibilidade intencional de formato, comportamento ou interface pública.
- **MINOR:** funcionalidade compatível adicionada.
- **PATCH:** correção compatível, incluindo correções de segurança quando possível.

Versões de formato de arquivo devem permanecer separadas da versão comercial da aplicação e ter uma matriz de compatibilidade explícita.

## Preparação

1. Definir escopo e congelar mudanças não relacionadas.
2. Atualizar changelog, roadmap, documentação e avisos de terceiros.
3. Confirmar versões suportadas de Python e sistemas operacionais.
4. Regenerar locks por processo revisado e reproduzível.
5. Testar migração e leitura de dados criados por versões suportadas.

## Checklist de segurança

- [ ] Revisar mudanças em criptografia, KDF, formatos, Vault, KeyGuard e containers.
- [ ] Executar vetores de teste para senha incorreta, truncamento, corrupção e dados anexados.
- [ ] Verificar tratamento de caminhos, permissões, temporários e escrita atômica.
- [ ] Revisar logs e mensagens para dados sensíveis.
- [ ] Avaliar dependências e advisories conhecidos.
- [ ] Confirmar que achados críticos foram resolvidos ou documentados antes da publicação.
- [ ] Atualizar `SECURITY.md` e o modelo de ameaça quando necessário.

## Checklist de documentação

- [ ] Registrar mudanças em `CHANGELOG.md` sem inventar datas ou compatibilidade.
- [ ] Atualizar instalação, uso, dependências e limitações.
- [ ] Publicar notas de release com mudanças incompatíveis e caminho de migração.
- [ ] Conferir links, licença e avisos de terceiros.

## Checklist de CI e artefatos

- [ ] Executar testes automatizados em matriz de plataformas suportadas.
- [ ] Tornar lint, análise de segurança e testes relevantes bloqueantes.
- [ ] Construir artefatos em ambiente isolado e reproduzível.
- [ ] Gerar hashes criptográficos e inventário de componentes.
- [ ] Testar instalação e remoção em máquinas limpas.
- [ ] Preservar logs e resultados necessários à rastreabilidade.

## Publicação

1. Criar tag apenas após todos os checks obrigatórios.
2. Publicar notas com limitações, compatibilidade e créditos.
3. Anexar artefatos e hashes produzidos pelo pipeline aprovado.
4. Atualizar canais de documentação sem apagar histórico.
5. Monitorar regressões e preparar correção quando necessário.

Assinatura de tags, releases e artefatos é uma meta futura. Quando implementada, chaves, rotação, revogação e verificação devem ser documentadas; não basta adicionar uma assinatura sem política operacional.
