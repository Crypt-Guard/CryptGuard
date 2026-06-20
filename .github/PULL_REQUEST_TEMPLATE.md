## Resumo

Descreva o problema e a solução proposta. Explique por que esta mudança pertence ao escopo do pull request.

## Tipo de mudança

- [ ] Correção de bug
- [ ] Nova funcionalidade
- [ ] Documentação
- [ ] Testes ou qualidade
- [ ] Hardening ou segurança
- [ ] Manutenção/CI
- [ ] Mudança incompatível

## Impacto em segurança

Descreva ameaças afetadas, novos riscos, dados sensíveis envolvidos e mitigações. Se não houver impacto, justifique brevemente.

Se o PR mudar criptografia, formato de arquivo, KDF, Vault, KeyGuard, containers, autenticação, secure delete, logs ou controles de segurança, explique obrigatoriamente:

- compatibilidade de leitura e escrita;
- migração ou rollback;
- risco de perda ou exposição de dados;
- vetores de teste e comportamento em falhas.

## Testes realizados

Liste comandos, ambientes e resultados. Não declare cobertura sem anexar um relatório verificável.

```text
# comandos e resultados relevantes
```

## Documentação

- [ ] Documentação atualizada
- [ ] Changelog atualizado, quando aplicável
- [ ] Não é necessária atualização de documentação, com justificativa abaixo

## Checklist

- [ ] O escopo está limitado e não inclui alterações incidentais.
- [ ] Revisei o diff completo e removi dados sensíveis.
- [ ] Considerei compatibilidade e arquivos persistentes.
- [ ] Executei os checks disponíveis ou expliquei por que não foi possível.
- [ ] Li o guia de contribuição e o Código de Conduta.
- [ ] Vulnerabilidades exploráveis foram comunicadas de forma privada.

## Observações adicionais

Inclua limitações, decisões pendentes ou contexto para a revisão.
