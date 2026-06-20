# Suporte

## Onde buscar ajuda

Use as [issues do GitHub](https://github.com/Crypt-Guard/CryptGuard/issues) para problemas reproduzíveis, dúvidas de uso e sugestões que possam ser discutidas publicamente. Antes de abrir uma issue, procure relatos existentes e consulte a [documentação](docs/USAGE.md).

Classifique a solicitação corretamente:

- **Bug:** comportamento atual diverge do esperado e pode ser reproduzido.
- **Dúvida:** pedido de orientação sem defeito confirmado.
- **Feature request:** proposta de capacidade nova ou mudança de comportamento.
- **Vulnerabilidade:** falha explorável de segurança; siga exclusivamente [SECURITY.md](SECURITY.md).

## Informações úteis

Inclua versão ou commit, sistema operacional, versão do Python, passos mínimos, resultado esperado e resultado atual. Logs devem ser reduzidos ao trecho necessário.

Antes de compartilhar logs:

- remova nomes de usuário, caminhos privados e nomes de arquivos sensíveis;
- remova senhas, chaves, tokens, cabeçalhos e conteúdos criptografados reais;
- substitua dados pessoais por exemplos sintéticos;
- confira anexos e metadados antes do envio.

## Recuperação de dados

O projeto não possui mecanismo de recuperação de senha. Se a senha for perdida, os dados protegidos podem se tornar permanentemente inacessíveis.

Não tente “reparar” manualmente um arquivo que falhou na autenticação. Alterar bytes, cabeçalhos ou metadados pode destruir evidências úteis e não restaura a autenticidade. Preserve o original, trabalhe em uma cópia e recupere um backup conhecido quando possível.

O suporte comunitário não garante recuperação, prazo de resposta ou compatibilidade com arquivos corrompidos e formatos não documentados.
