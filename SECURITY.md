# Política de Segurança

O CryptGuard fornece mecanismos de criptografia autenticada, mas nenhum software oferece segurança absoluta. Esta política descreve versões cobertas, modelo de ameaça, limitações e o processo de divulgação responsável.

Para detalhes técnicos e premissas, consulte o [Modelo de Segurança](docs/SECURITY_MODEL.md).

## Versões suportadas

| Linha | Suporte de segurança |
| --- | --- |
| 3.x em desenvolvimento | Sim, na branch principal |
| 2.x | Não; documentação e formatos legados |
| 1.x e anteriores | Não |

O projeto ainda não mantém um calendário formal de releases. Correções são direcionadas à linha 3.x atual.

## Escopo de segurança

Relatos relevantes incluem, entre outros:

- falhas de confidencialidade ou autenticação no formato `.cg2` v5;
- derivação, armazenamento, exposição ou comparação inadequada de chaves e senhas;
- adulteração não detectada de cabeçalhos, quadros, metadados, Vaults ou containers `.vault`;
- travessia de diretórios, escrita insegura ou substituição inesperada de arquivos;
- vazamento de informações sensíveis por logs, temporários ou mensagens de erro;
- bypasses de controles de desbloqueio ou integração entre Vault, KeyGuard e containers.

## Modelo de ameaça

O modelo principal considera um atacante com acesso offline aos arquivos criptografados, mas sem a senha. Nesse cenário, espera-se que uma senha adequada, a KDF Argon2id e a criptografia autenticada dificultem a recuperação do conteúdo e detectem alterações nos dados protegidos.

O projeto busca proteger:

- conteúdo de arquivos criptografados;
- integridade de cabeçalhos, quadros e metadados autenticados;
- dados armazenados pelos componentes Vault, KeyGuard e containers, conforme os formatos implementados;
- operações temporárias e segredos em memória dentro das limitações do sistema operacional e do runtime Python.

## Fora do escopo

As seguintes condições não são neutralizadas pelo CryptGuard:

- máquina comprometida por malware, keylogger ou ferramenta de acesso remoto;
- sistema operacional, kernel, hipervisor ou firmware malicioso;
- atacante com acesso root, administrador ou depuração equivalente durante o uso;
- captura de texto claro por swap, hibernação, crash dump ou periféricos;
- snapshots, backups, sincronizadores ou históricos do sistema que preservem arquivos ou texto claro;
- senhas fracas, reutilizadas, compartilhadas de forma insegura ou perdidas;
- engenharia social, coerção ou divulgação voluntária de credenciais;
- exposição causada por aplicações externas após a descriptografia;
- ataques físicos e forenses contra um equipamento ligado e desbloqueado.

Hidden volumes e decoy volumes não fazem parte da linha 3.x. Referências anteriores são históricas e não constituem uma garantia disponível.

## Como reportar uma vulnerabilidade

Não abra issue pública, discussão ou pull request com detalhes de uma vulnerabilidade explorável.

Envie o relato para **cryptguard737@gmail.com** com:

- descrição e impacto esperado;
- versão, commit ou estado da branch analisada;
- ambiente e pré-condições;
- passos mínimos para reprodução;
- prova de conceito ou vetores de teste, quando seguros;
- sugestões de mitigação, se disponíveis.

Evite anexar dados reais, senhas, chaves ou arquivos privados. Use conteúdo sintético e indique no assunto que se trata de um relato de segurança.

## Processo de resposta

Os mantenedores buscarão confirmar o recebimento, avaliar a severidade, solicitar informações adicionais quando necessário e coordenar uma correção antes da divulgação pública. O projeto não oferece um SLA rígido; o prazo depende da complexidade, disponibilidade dos mantenedores e impacto observado.

Quando apropriado, a correção será acompanhada de documentação, nota de segurança ou orientação de atualização. A divulgação coordenada deve evitar expor usuários antes que uma mitigação esteja disponível.

## Recomendações de uso seguro

- Use senhas longas, únicas e geradas aleatoriamente.
- Proteja a senha por canal separado dos arquivos criptografados.
- Mantenha sistema operacional, Python e dependências atualizados.
- Trabalhe somente em máquinas confiáveis e evite privilégios administrativos desnecessários.
- Mantenha backups testados dos arquivos criptografados, Vaults e containers.
- Use **Verify** antes de processar arquivos recebidos de terceiros.
- Não tente modificar ou reparar manualmente dados autenticados corrompidos.
- Combine o projeto com criptografia de disco completa e uma política de backup adequada.

## Exclusão segura

A sobrescrita e remoção de arquivos é apenas *best-effort*. SSDs e NVMe usam *wear-leveling*; sistemas de arquivos podem usar journaling, compressão ou *copy-on-write*; snapshots e backups podem reter blocos antigos. Para reduzir esse risco, use criptografia de disco desde o início e os mecanismos de descarte seguro oferecidos pelo fabricante ou pelo sistema.

## Conformidade de exportação

Software criptográfico pode estar sujeito a regras locais de uso, importação e exportação. Distribuidores e usuários são responsáveis por avaliar as normas aplicáveis à sua jurisdição. Este texto não constitui aconselhamento jurídico nem uma classificação formal de exportação.

Consulte também o [Modelo de Segurança detalhado](docs/SECURITY_MODEL.md).
