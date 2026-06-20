# Modelo de Segurança

## Objetivo

O CryptGuard busca proteger a confidencialidade e a integridade de arquivos armazenados contra um atacante que obtenha os artefatos criptografados, mas não possua a senha nem controle o ambiente durante a operação legítima.

Não existe garantia de segurança absoluta. As garantias dependem da implementação, das bibliotecas, da qualidade da senha, dos parâmetros da KDF e da integridade da máquina.

## Modelo de ameaça

O cenário principal considera:

- acesso offline a arquivos `.cg2`, Vaults ou containers `.vault`;
- tentativa de adivinhar senhas;
- truncamento, corrupção, substituição ou anexação de dados;
- observação de metadados que permaneçam fora da região protegida.

Não são controlados pelo aplicativo:

- malware, keyloggers ou captura da tela;
- root, administrador, kernel ou hipervisor hostil;
- leitura de memória por um processo privilegiado;
- swap, hibernação, crash dumps, snapshots e backups do sistema;
- acesso ao texto claro antes da criptografia ou depois da descriptografia;
- coerção, engenharia social ou compartilhamento inseguro da senha.

## Garantias esperadas

Sob as premissas do modelo, espera-se:

- confidencialidade do conteúdo com senha e KDF adequadas;
- detecção de alterações nos dados cobertos pela autenticação;
- rejeição de senha incorreta ou conteúdo corrompido sem tratar a saída como autêntica;
- vinculação entre payload, parâmetros e metadados incluídos na autenticação;
- geração de novos arquivos no formato v5 documentado.

Essas propriedades são objetivos de projeto e ainda exigem testes independentes e auditoria externa.

## Criptografia autenticada

O formato v5 documentado utiliza XChaCha20-Poly1305 SecretStream. Quadros são autenticados durante o fluxo, e um marcador final autenticado sinaliza o encerramento esperado. Cabeçalho e parâmetros relevantes são associados como AAD para detectar substituições que alterem a interpretação do payload.

Dados não devem ser liberados como confiáveis antes da autenticação aplicável. Truncamento, quadros inválidos e dados anexados devem resultar em falha controlada.

## Derivação de chaves

Argon2id deriva material de chave a partir da senha e de um salt. Custos de tempo, memória e paralelismo aumentam o custo de tentativas offline, mas não compensam senhas fracas. A calibração deve respeitar limites operacionais e permanecer autenticada quando armazenada com o formato.

Senhas longas e aleatórias continuam sendo a principal defesa contra adivinhação.

## Metadados

O formato v5 documenta metadados finais autenticados, incluindo nome, extensão, tamanho real, padding e contagem de blocos. O padding de até 16 KiB reduz apenas parte da informação de tamanho; não oculta completamente padrões de uso, horários, quantidade de arquivos ou tamanho aproximado.

Metadados externos criados pelo sistema de arquivos, sincronizador ou backup permanecem fora da proteção do formato.

## Vault e KeyGuard

O Vault principal organiza arquivos criptografados. O KeyGuard possui geração de senhas e armazenamento próprio. Cada mecanismo tem formato, senha e ciclo de desbloqueio que devem ser avaliados separadamente.

Um Vault aberto em uma máquina comprometida não protege contra captura dos dados em uso. Perda de senha ou corrupção sem backup pode causar perda permanente.

## Containers seguros

Containers `.vault` agrupam itens selecionados para transporte ou backup e são documentados com Argon2id e SecretStream. Eles não substituem backups independentes. A senha do container deve ser diferente de outras credenciais e enviada por canal separado.

Importação e extração devem ser tratadas como entrada não confiável, com validação de autenticação, nomes e destinos antes da escrita.

## Hardening e exclusão segura

Bloqueio e limpeza de memória, comparações constantes, proteção de processo, arquivos temporários e mascaramento de logs reduzem riscos específicos, mas não eliminam cópias feitas pelo runtime, pelas bibliotecas ou pelo sistema operacional.

Exclusão segura é apenas *best-effort*. SSDs, NVMe, wear-leveling, journaling, *copy-on-write*, snapshots e backups podem preservar blocos. Use criptografia de disco completa desde a instalação e políticas adequadas de descarte de mídia.

## Responsabilidade operacional

- Mantenha cópias de segurança testadas dos artefatos criptografados.
- Nunca use arquivos reais em relatos públicos ou testes de terceiros.
- Verifique hashes e procedência do código e de futuras releases.
- Atualize dependências após avaliar compatibilidade e avisos de segurança.
- Consulte também a [Política de Segurança](../SECURITY.md).
