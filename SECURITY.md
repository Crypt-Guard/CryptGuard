# 🛡️ Aviso de Segurança do CryptGuard

## ⚠️ Informações Importantes

### Segurança Relativa e Responsabilidade do Usuário

O CryptGuard foi desenvolvido para oferecer uma solução robusta de criptografia utilizando:
- **ChaCha20Poly1305** para criptografia autenticada,
- **Argon2id** para derivação de chaves seguras,
- **Reed-Solomon** para correção de erros,
- **Volumes ocultos com negação plausível** e um novo recurso de **Key Rolling / Re-encryption** para atualizar a senha da parte real do volume oculto sem expor a parte falsa.

Entretanto, nenhuma solução pode garantir segurança absoluta. O uso do CryptGuard deve ser acompanhado de práticas e auditorias de segurança, e os dados protegidos são de responsabilidade exclusiva do usuário.

### Auditoria e Revisão Externa

Recomendamos que:
1. O CryptGuard seja submetido a auditorias externas independentes;
2. Especialistas em segurança revisem e testem a implementação em ambientes controlados;
3. O software seja utilizado juntamente com políticas de segurança e backups regulares.

## 🔒 Melhores Práticas de Segurança

1. **Gerenciamento de Senhas e Arquivos-chave**
   - Utilize senhas fortes (idealmente 12 ou mais caracteres) com letras maiúsculas, minúsculas, dígitos e símbolos.
   - Opte pelo modo “Senha + Arquivo-chave” quando possível para aumentar a entropia.
   - A autenticação é realizada com dupla verificação para reduzir erros de digitação.
   - Nunca reutilize senhas e mantenha os arquivos-chave em locais seguros.

2. **Proteção dos Dados e Metadados**
   - Os metadados são cifrados com ChaCha20Poly1305 e armazenados em arquivos `.meta`, contendo inclusive a extensão original dos arquivos para preservar a integridade dos dados.
   - Dados sensíveis, como senhas e chaves derivadas, são tratados com cuidado e seus buffers são zeroizados após o uso.

3. **Volumes Ocultos e Re-Key (Key Rolling)**
   - Volumes ocultos separam dados falsos e reais para permitir negação plausível.
   - A funcionalidade de **Key Rolling / Re-encryption** permite que a senha do volume real seja alterada sem expor a parte falsa.
   - Recomenda-se realizar re-key periodicamente e manter um registro seguro das novas credenciais.

4. **Ambiente Seguro**
   - Mantenha o sistema operacional e todas as dependências atualizados.
   - Utilize antivírus, firewalls e outras ferramentas de proteção.
   - Realize backups regulares dos dados e dos metadados, garantindo a recuperação em caso de falhas.

## ⚖️ Isenção de Responsabilidade

Os desenvolvedores do CryptGuard fornecem o software "como está", sem garantias de segurança absoluta. Não nos responsabilizamos por:
- Danos diretos ou indiretos decorrentes do uso ou mau uso do software,
- Perdas de dados,
- Falhas de segurança não identificadas,
- Problemas de compatibilidade ou configurações incorretas.

O uso do CryptGuard é de inteira responsabilidade do usuário.

## 📜 Conformidade Legal e Regulamentar

### Regulamentações
A criptografia e o uso de tecnologias de segurança podem estar sujeitos a regulamentações específicas que variam conforme o país, a região e o setor de atuação.

### Responsabilidade do Usuário
É responsabilidade do usuário garantir que:
- O uso do CryptGuard esteja em conformidade com a legislação local (como a LGPD no Brasil);
- As configurações e práticas de segurança adotadas atendam às exigências regulamentares do seu setor.

## 🆘 Suporte e Contato

Para reportar vulnerabilidades ou problemas de segurança:
1. NÃO abra uma issue pública.
2. Envie um e-mail para: [cryptguard737@gmail.com](mailto:cryptguard737@gmail.com).
3. Utilize, se disponível, nossa chave PGP para comunicações seguras.

---

Este aviso visa orientar os usuários sobre as limitações e boas práticas de segurança ao utilizar o CryptGuard, que agora apresenta uma arquitetura modular aprimorada, suporte a key rolling para volumes ocultos e outras melhorias projetadas para oferecer uma solução robusta, mas que requer uma gestão cuidadosa e auditoria contínua.
