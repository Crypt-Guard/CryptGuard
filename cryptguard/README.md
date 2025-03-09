**CryptGuard** é uma ferramenta de criptografia de dados com suporte a **volumes ocultos** para oferecer **negação plausível**. Desenvolvida em Python, ela permite criar volumes criptografados nos quais é possível armazenar dados confidenciais com forte proteção criptográfica. Seu principal diferencial é a capacidade de criar um segundo volume escondido dentro do volume principal, de forma que mesmo sob coação o usuário possa revelar apenas o volume externo sem evidenciar a existência dos dados mais sensíveis.

## Introdução

CryptGuard foi concebido com o propósito de proteger dados sigilosos em repouso, fornecendo uma camada adicional de segurança através de um volume oculto. As principais funcionalidades incluem:

- **Criptografia Forte**: Utiliza algoritmos modernos (como AES de 256 bits ou equivalente) e derivação de chaves via Argon2 para assegurar a confidencialidade dos dados.
- **Volume Oculto (Hidden Volume)**: Permite criar um volume interno secreto dentro de um volume criptografado externo, viabilizando a negação plausível em casos de coação.
- **Derivação Segura de Chaves**: Emprega Argon2 (função de derivação de chave robusta) para converter senhas em chaves criptográficas, dificultando ataques de força bruta.
- **Processamento de Grandes Arquivos**: Suporta criptografia em **streaming**, dividindo dados em blocos para processar arquivos grandes sem carregar tudo na memória.
- **Interface Modular**: Código organizado em módulos independentes, facilitando manutenção e extensões por desenvolvedores.

Este README técnico destina-se a desenvolvedores que desejam entender o funcionamento interno do CryptGuard para modificá-lo ou atualizá-lo. A seguir, detalhamos a estrutura do código, explicamos a implementação do volume oculto e descrevemos o papel de cada módulo, com exemplos de uso e dicas de melhores práticas para expansão da funcionalidade.

## Estrutura do Código

O projeto está organizado em múltiplos módulos Python, cada um responsável por uma parte da lógica do CryptGuard. Abaixo está a estrutura geral dos arquivos e a responsabilidade de cada módulo:

- **`password_utils.py`** – Responsável por funções de validação de senha e por gerenciar a autenticação, incluindo a verificação de um arquivo-chave, quando utilizado.
- **`rs_codec.py`** – Implementa a codificação e decodificação Reed-Solomon para garantir a integridade dos dados e oferecer mecanismos de correção de erros nos chunks cifrados.
- **`config.py`** – Define configurações e constantes globais usadas por todo o sistema (tamanhos de chave, parâmetros do Argon2, tamanho de bloco, etc.).
- **`utils.py`** – Funções utilitárias genéricas usadas em vários módulos (por exemplo, manipulação de bytes, conversões, geração de valores aleatórios seguros, etc.).
- **`argon_utils.py`** – Lógica de derivação de chaves usando Argon2. Contém funções para gerar a chave criptográfica a partir da senha do usuário e um salt.
- **`chunk_crypto.py`** – Implementa a criptografia e descriptografia em blocos (chunks) de dados. Fornece funções de baixo nível para cifrar/decifrar segmentos de um arquivo usando a chave derivada.
- **`metadata.py`** – Define a estrutura de metadados do volume criptografado (header). Esse módulo lida com a criação e interpretação do cabeçalho do volume, incluindo informações como salt, parâmetros de KDF, tamanho de volume oculto, etc.
- **`hidden_volume.py`** – Gerencia a lógica de volumes ocultos. Funções para criação de um volume criptografado (com ou sem volume oculto) e para acesso/extração do volume escondido dentro do volume externo.
- **`streaming.py`** – Fornece mecanismos de criptografia **em streaming** (fluxo contínuo). Usado para ler ou escrever dados criptografados em partes, útil para não carregar arquivos inteiros em memória.
- **`single_shot.py`** – Oferece funções de criptografia **de uma vez só** (single shot), que processam o dado inteiro de uma vez. Indicado para arquivos menores ou operações simples.
- **`main.py`** – Ponto de entrada do aplicativo (CLI). Analisa argumentos de linha de comando e coordena as operações de criar volumes, criptografar ou descriptografar arquivos, utilizando os módulos acima.
- **`__init__.py`** – Inicializa o pacote `cryptguard`. Geralmente vazio ou utilizado para expor interfaces públicas do pacote (por exemplo, importações convenientes ou informações de versão).

Essa separação modular facilita a compreensão e manutenção: cada componente lida com um aspecto específico (configurações, criptografia, volume oculto, etc.), permitindo que desenvolvedores modifiquem partes isoladamente sem impactar todo o sistema.

## Volume Oculto e Segurança

O **volume oculto** é a principal característica de segurança avançada do CryptGuard. Ele permite armazenar dados secretos dentro de um volume criptografado de tal forma que a própria existência desses dados seja disfarçada. A seguir, explicamos como isso é implementado e como protege os dados:

- **Conceito de Negação Plausível**: Ao criar um volume com suporte a ocultação, o usuário define duas senhas – uma para o volume externo (dados menos sensíveis ou chamativos) e outra para o volume interno oculto (dados altamente confidenciais). Caso seja forçado a revelar a senha, o usuário pode fornecer apenas a senha do volume externo. Quem obtiver essa senha consegue acessar somente os dados do volume externo, enquanto o volume oculto permanece inacessível e indetectável, pois seus dados parecem aleatórios dentro do arquivo criptografado.
- **Implementação do Volume Oculto**: O CryptGuard aloca um único arquivo container criptografado. Dentro desse container:
  - O **volume externo** ocupa o espaço inicial do arquivo e possui seu próprio cabeçalho de metadados e região de dados criptografados.
  - O **volume oculto** é armazenado em uma porção reservada do mesmo arquivo (tipicamente no final ou em áreas não utilizadas pelo volume externo). Seus dados também são cifrados e só podem ser interpretados com a segunda senha.  
  Importante: o espaço do volume oculto é preenchido com dados aleatórios quando o volume é criado, de forma que, sem a senha correta, ele é indistinguível de espaço livre aleatório.
- **Proteção dos Dados**: Ambos os volumes (externo e oculto) usam criptografia forte. A senha do usuário nunca é usada diretamente como chave; em vez disso, o módulo de derivação (`argon_utils.py`) aplica Argon2 (um KDF robusto) junto com um salt aleatório (armazenado no cabeçalho) para gerar a chave de criptografia. Isso torna ataques de força bruta muito mais difíceis, pois Argon2 impõe um alto custo computacional para cada tentativa de senha.
- **Isolamento de Metadados**: Os metadados do volume (definidos em `metadata.py`) incluem informações necessárias para montar/abrir o volume: um identificador ou número de versão, o salt do Argon2, parâmetros do Argon2 (tempo de processamento, memória, etc.), tamanho do volume oculto, entre outros. Esses metadados do volume externo são armazenados no início do arquivo container, cifrados com a chave derivada da senha externa. Já os metadados do volume oculto são armazenados separadamente (por exemplo, em outra área conhecida do arquivo, possivelmente logo após o espaço do volume externo ou no final do arquivo), cifrados com a chave derivada da senha oculta. Assim, conhecer a senha externa permite decifrar apenas os metadados do volume externo – os do volume oculto permanecem inacessíveis sem a segunda senha.
- **Operação de Abertura do Volume**: Ao abrir um volume criptografado, o CryptGuard tenta decifrar o cabeçalho de metadados usando a senha fornecida. Se a senha corresponder ao volume externo, os metadados se decifrarão corretamente (validação por algum campo de integridade ou assinatura interna) e o sistema monta o volume externo. Se a senha corresponder ao volume oculto, a decodificação do cabeçalho externo falhará; em seguida, o software pode tentar decifrar a área de metadados do volume oculto com essa senha. Caso seja válida, monta-se o volume oculto. Se nenhuma das tentativas resultar em metadados válidos, a senha é considerada incorreta. Esse processo garante que um invasor com senha apenas do volume externo não consiga detectar ou montar o volume oculto.
- **Integridade e Confidencialidade**: Todos os dados armazenados, tanto no volume externo quanto no oculto, são cifrados. Opcionalmente, cada bloco de dados pode incluir verificações de integridade/autenticidade (por exemplo, tags de autenticidade, HMACs) para detectar modificações indevidas nos dados cifrados. (Obs.: Se o CryptGuard implementa uma cifra autenticada, como AES-GCM, a integridade vem inclusa; caso contrário, essa funcionalidade pode ser adicionada via HMAC em futuros aprimoramentos).
- **Restrições de Escrita no Volume Externo**: Uma vez que um volume oculto é criado dentro de um container, é crucial que o volume externo não sobrescreva os dados do volume oculto. O CryptGuard ao criar o volume oculto reserva explicitamente uma porção do arquivo para ele. A escrita de dados no volume externo deve ser limitada ao seu espaço alocado. Em cenários onde o volume externo pode ser montado para escrita, uma prática recomendada (inspirada no VeraCrypt/TrueCrypt) é solicitar também a senha do volume oculto durante a montagem externa para que o software possa evitar gravar acidentalmente em áreas ocupadas pelo volume oculto. Caso o CryptGuard ainda não implemente essa proteção dinâmica, **desenvolvedores devem ter cautela** ao adicionar tal funcionalidade para garantir que o volume oculto não seja corrompido.

Em resumo, a estratégia de segurança do CryptGuard combina criptografia forte com design cuidadoso de armazenamento para oferecer negação plausível. Mesmo que um adversário obtenha o arquivo criptografado, sem a senha correta ele só verá dados aleatórios; e mesmo com a senha externa, não há indicações de que um segundo volume existe. Para o usuário legítimo, entretanto, o acesso aos dados ocultos é transparente ao fornecer a senha secundária.

## Funcionamento de Cada Módulo

Nesta seção, detalhamos o funcionamento interno de cada módulo do CryptGuard e como um desenvolvedor pode modificá-los ou estendê-los. Entender a interação entre esses componentes é fundamental para realizar alterações de forma segura sem introduzir regressões. Os exemplos de uso fornecidos ajudam a ilustrar como os módulos trabalham juntos.

### config.py – Configurações Globais

O módulo `config.py` concentra constantes e parâmetros globais de configuração usados em toda a aplicação. Isso inclui, entre outros:

- **Tamanhos e Comprimentos**: por exemplo, tamanho do salt (em bytes) para Argon2, comprimento da chave derivada (por exemplo, 256 bits), tamanho de blocos de criptografia, etc.
- **Parâmetros do Argon2**: valores padrão para iterações (tempo), memória e paralelismo usados na derivação de chave. Por exemplo, `ARGON_T_COST` (custo de tempo/número de iterações), `ARGON_M_COST` (memória em KiB), `ARGON_PARALLELISM` (número de threads).
- **Algoritmos de Criptografia**: especificação do algoritmo e modo de operação padrão (por exemplo, AES em modo XTS ou GCM) e tamanho de bloco. Se o projeto utiliza uma biblioteca de criptografia, pode definir aqui strings ou identificadores para escolher a cifra.
- **Outros**: tamanho dos metadados (header) do volume, identificador de versão do formato, e quaisquer flags ou opções default.

*Como funciona:* Esses valores são importados por outros módulos para assegurar consistência. Por exemplo, `argon_utils.py` consulta `config.py` para saber qual o tamanho do salt e parâmetros Argon2 usar, e `chunk_crypto.py` pode usar a constante de tamanho de bloco definida aqui.

*Como modificar:* Desenvolvedores podem ajustar parâmetros em `config.py` para atualizar configurações globais. Por exemplo, aumentar o custo do Argon2 (para reforçar segurança contra ataques de força bruta) ou trocar o algoritmo de cifragem (se quiser implementar ChaCha20-Poly1305 em vez de AES, por exemplo). Tais mudanças afetam todo o sistema, então é importante verificar compatibilidade – volumes criados com configurações antigas talvez precisem de migração se o formato mudar (ex.: mudança no tamanho de metadados ou algoritmo deve vir acompanhada de um incremento de versão e possivelmente procedimentos de conversão). Mantenha `config.py` como fonte da verdade para evitar “números mágicos” espalhados pelo código.

### utils.py – Funções Utilitárias

O `utils.py` contém funções auxiliares de uso geral que não se encaixam especificamente nos outros componentes. Exemplos de funcionalidades que podem estar presentes neste módulo:

- **Geração de Dados Aleatórios Seguros**: função para gerar bytes aleatórios (por exemplo, usando `os.urandom()` ou via biblioteca de criptografia) para usos diversos como salt, IV (vetor de inicialização) ou preenchimento.  
- **Manipulação de Bytes e Strings**: conversão de endereços ou inteiros para bytes e vice-versa, padding de dados para alinhar em blocos, formatação de valores de tamanho (ex.: converter tamanho em MB para bytes).
- **Funções de Apoio Criptográfico**: por exemplo, limpeza segura de memória (overwrite de buffers de texto plano após uso), ou cálculo de hash/HMAC se necessário em vários lugares.
- **Tratamento de Erros e Logs**: possivelmente utilidades para logar eventos de criptografia ou lançamento de exceções customizadas (como uma exceção específica para "senha incorreta" ou "dados corrompidos").

*Como funciona:* O utils serve de biblioteca de apoio para os demais módulos. Por exemplo, ao criar um volume, o `hidden_volume.py` pode chamar `utils.py` para gerar o salt aleatório do cabeçalho. Se houver necessidade de converter representações (como transformar uma senha em encoding específico antes de derivar a chave), isso pode estar em utils. Mantê-las isoladas facilita testes unitários e evita duplicação de código.

*Como modificar:* Ao adicionar novas funcionalidades que sejam utilizadas em múltiplos módulos, considere implementá-las aqui. Por exemplo, se for incluir uma função de verificação de integridade repetida em vários lugares, coloque-a em utils. Certifique-se de escrever funções genéricas e bem testadas, pois um bug aqui pode afetar várias partes do CryptGuard. Se alterar alguma função existente (como o gerador de aleatórios), garanta que continue usando fontes criptograficamente seguras. Em resumo, `utils.py` deve conter funções **puramente utilitárias** – modifique-o conforme necessário, mas evite inserir lógica de alto nível nele (que deve ficar nos módulos principais).

### argon_utils.py – Derivação de Chaves (KDF)

Este módulo implementa a derivação de chaves usando o algoritmo **Argon2**, uma das funções de derivação de senha mais seguras atualmente. O Argon2 protege contra ataques de força bruta impondo alto custo computacional e de memória para cada tentativa de descoberta de chave.

Principais aspectos do `argon_utils.py`:

- **Função de Derivação**: Provavelmente a função principal aqui é algo como `derivar_chave(senha: str, salt: bytes) -> bytes`. Ela utiliza os parâmetros definidos em `config.py` (p.ex. iterações, memória, comprimento da chave) para rodar o Argon2 e produzir a chave de criptografia a partir da senha fornecida.
- **Biblioteca de Suporte**: Internamente, a implementação pode usar uma biblioteca Python, como `argon2-cffi` ou similar, ou eventualmente chamar uma função de baixo nível. Os parâmetros (senha, salt, t_cost, m_cost, parallelism) são passados conforme `config.py` define.
- **Salt Aleatório**: A geração do salt *não* é feita aqui; provavelmente o salt é gerado via `utils.py` quando criando um volume e armazenado nos metadados. `argon_utils.py` apenas recebe o salt (do cabeçalho) para derivar a mesma chave quando precisar decifrar.

*Como funciona:* Quando um novo volume é criado, `argon_utils.py` é usado para derivar a chave mestre de criptografia a partir da senha do usuário. Primeiro gera-se um salt aleatório (via utils) e salva-se esse salt no cabeçalho. Depois, passa-se a senha e o salt para a função Argon2, obtendo uma chave de, por exemplo, 256 bits. Essa chave então é usada pelo módulo de criptografia (chunk_crypto) para cifrar os dados. No momento de abrir um volume existente, o processo se repete: lê-se o salt do cabeçalho, aplica-se Argon2 com a senha fornecida e se obtém a chave para tentar decifrar os dados ou os metadados.

*Como modificar:* Caso desenvolvedores queiram trocar o esquema de derivação de chaves, este é o módulo a ser alterado. Por exemplo, para usar **scrypt** ou PBKDF2 em vez de Argon2, pode-se criar uma nova função aqui ou modificar a existente, lembrando de atualizar a forma como os parâmetros são tratados (e guardar novos parâmetros no metadado, se necessário). Se desejar ajustar a segurança, aumentar `t_cost` ou `m_cost` do Argon2 tornará a derivação mais lenta (melhorando segurança contra ataques, porém deixando a abertura de volume ligeiramente mais lenta para todos). Mantenha a compatibilidade: volumes antigos derivam a chave com os parâmetros antigos – uma solução é incluir nos metadados a identificação do algoritmo de KDF e seus parâmetros para que `argon_utils.py` possa aplicar o procedimento correto dependendo da versão do volume. Em resumo, mexa aqui para evoluir o KDF, mas teste exaustivamente a compatibilidade com volumes existentes e a resistência a ataques de senha.

### chunk_crypto.py – Criptografia de Dados em Blocos

O módulo `chunk_crypto.py` implementa as operações de criptografia e descriptografia de baixo nível, manipulando os dados efetivos do volume. O termo "chunk" (pedaço) refere-se ao processamento dos dados em blocos de tamanho fixo, o que é útil para streaming e para grandes arquivos. Principais responsabilidades e funcionamento:

- **Inicialização de Cifra**: Geralmente, antes de cifrar ou decifrar um bloco, é necessário inicializar um objeto de cifra (por exemplo, criar um objeto AES a partir da chave e IV correspondentes). `chunk_crypto.py` provavelmente fornece funções como `inicializar_cifra(chave, iv)` ou implementa diretamente dentro de funções de encriptação.
- **Cifrar e Decifrar Blocos**: Funções dedicadas, por exemplo `encrypt_chunk(data: bytes, key: bytes, iv: bytes) -> bytes` e `decrypt_chunk(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes`. Estas usam a biblioteca criptográfica subjacente para aplicar a cifra simétrica.
- **Modo de Operação**: O modo de criptografia escolhido influencia como os blocos são tratados:
  - Se for um modo de streaming ou CTR, cada chunk pode ser cifrado independentemente usando um contador ou IV único.
  - Se for GCM (um modo AEAD), cada bloco produzirá também um tag de autenticação que precisa ser armazenado/verificado.
  - Se for XTS (modo típico para criptografia de disco), o módulo pode dividir o volume em setores e criptografar cada setor com tweaks; contudo, XTS é mais complexo e requer 2 chaves derivadas, o que talvez seja demais para esta implementação caso tenha sido simplificada.
  - **Suposição**: É provável que um modo mais simples como **AES-GCM** seja usado para garantir confidencialidade e integridade por bloco. Nesse caso, cada chunk deve armazenar além do dado cifrado o tag de autenticação gerado.
- **Gerenciamento de IV/Nonce**: Para cada bloco cifrado, é importante usar um **IV (vetor de inicialização)** ou **nonce** único. O módulo pode definir que o IV do primeiro bloco seja derivado de algo (por exemplo, do salt ou parte do hash da chave) e depois incrementado ou calculado em função do índice do bloco para subsequentes. Outra estratégia é gerar IVs aleatórios por bloco e armazená-los junto com os dados cifrados (embora isso aumente o overhead). O `chunk_crypto.py` lida com esses detalhes para que outros módulos (streaming, single_shot) não precisem se preocupar com o baixo nível.
- **Tamanho de Bloco**: Definido em `config.py` (por exemplo, 64 KiB). O chunk_crypto pode ler essa constante para saber quantos bytes processar por vez. Exceto possivelmente o último bloco de um arquivo, que pode ser menor se o tamanho total não for múltiplo do tamanho do chunk – nesse caso, a função de criptografia deve adequar o padding ou tratamento do bloco final (por exemplo, usando padding padrão de cifra ou armazenando o tamanho real em algum lugar).
- **Autenticidade**: Se não for usado um modo autenticado nativamente, o módulo pode calcular um HMAC por bloco ou global para garantir que os dados não foram alterados indevidamente. No entanto, isso adiciona complexidade de gerenciamento de chaves (seria necessária uma chave HMAC separada ou derivar adicionalmente via Argon2). É algo a verificar no código; se não implementado, considere nas melhorias.

*Como funciona:* Quando um volume é montado (externo ou oculto), após derivar a chave pelo Argon2 (`argon_utils.py`), cada leitura/escrita de dados criptografados passa pelo `chunk_crypto`. Por exemplo, para escrever dados cifrados: divide-se o fluxo de bytes em blocos do tamanho configurado, para cada bloco gera-se um IV (pode ser incrementando um contador ou outro esquema), então cifra-se o bloco com a chave e IV obtidos. O resultado (e possivelmente o tag de autenticação) é escrito no arquivo container. Para leitura (descriptografia), o processo se inverte: para cada bloco lido do arquivo, recupera-se (ou recalcula-se) o IV correspondente, decifra-se o bloco com a chave derivada e obtém-se o texto plano original. Tudo isso deve ocorrer de forma transparente para quem usar níveis superiores (streaming ou single_shot).

*Exemplo de uso:* Um desenvolvedor pode usar funções do `chunk_crypto.py` diretamente se quiser criptografar manualmente um bloco de dados. Exemplo simplificado:
```python
from cryptguard import chunk_crypto, config
key = b'\x01\x02...32byteskey...'       # chave derivada previamente
iv  = b'\x00\x00\x00\x00...16bytesiv...' # IV para o bloco (16 bytes para AES)
plaintext = b"Dados confidenciais..."
ciphertext = chunk_crypto.encrypt_chunk(plaintext, key, iv)
# ... salvar ciphertext no arquivo ...
```
Da mesma forma, para decifrar:
```python
decrypted = chunk_crypto.decrypt_chunk(ciphertext, key, iv)
assert decrypted == plaintext
```
No uso normal do CryptGuard via suas camadas superiores, o desenvolvedor não precisa gerenciar manualmente IVs por bloco – isso é tratado internamente. Mas para modificar o comportamento, por exemplo, mudar o modo de geração de IV ou implementar um novo algoritmo, `chunk_crypto.py` é o local apropriado.

*Como modificar:* Se quiser trocar o algoritmo de criptografia ou o modo de operação, o desenvolvedor deve modificar as funções em `chunk_crypto.py`. Por exemplo, para usar **ChaCha20-Poly1305** em vez de AES, pode-se utilizar a biblioteca de criptografia apropriada e ajustar os tamanhos de chave e nonce. Ao fazer isso, lembre-se de atualizar `config.py` com constantes adequadas (tamanho da chave de 256 bits permanece, nonce de 96 bits para ChaCha20, etc.) e garantir que `metadata.py` capture quaisquer informações necessárias (como talvez um identificador de algoritmo para saber como decifrar). Testes devem confirmar que volumes criados com o novo algoritmo ainda podem ser reconhecidos ou que a mudança de formato seja claramente indicada para evitar tentativas de decifração com o método errado. Outro possível ajuste: aumentar o tamanho de bloco para melhorar desempenho (blocos maiores = menos operações de KDF de IV ou menos tags, porém consomem mais RAM por bloco). Qualquer alteração em `chunk_crypto.py` deve ser acompanhada de testes de encriptação/desencriptação para verificar que os dados recuperados são idênticos aos originais e que erros de senha se comportam conforme esperado (dados aleatórios de uma senha errada não devem decifrar para algo legível).

### metadata.py – Metadados do Volume Criptografado

O módulo `metadata.py` define a estrutura do cabeçalho (header) do volume criptografado e fornece funcionalidades para manipular essa estrutura. Os metadados são críticos pois armazenam informações necessárias para derivar chaves e entender a organização do volume, tanto do externo quanto do oculto.

Características típicas contidas nos metadados (supondo uma classe, por exemplo, `VolumeMetadata`):

- **Identificador/Magic e Versão**: Um valor fixo que identifica o arquivo como um volume CryptGuard e possivelmente um número de versão do formato. Isso ajuda a validar se a decifração do cabeçalho foi bem-sucedida (por exemplo, espera-se ler um “MAGIC” específico após tentar decifrar com a senha; se não bater, a senha está errada ou o arquivo não é válido).
- **Salt**: O salt aleatório usado para derivação da chave via Argon2. Provavelmente armazenado em texto claro no cabeçalho *criptografado* (ou seja, dentro do cabeçalho que é cifrado). Ao tentar abrir o volume, o software lê o arquivo, obtém o blob de metadados cifrados, tenta decifrar com a senha fornecida; se conseguir, extrai o salt e então aplica Argon2. (Alternativamente, o salt pode ficar fora do trecho cifrado para permitir derivar a chave antes de decifrar o restante do cabeçalho – mas isso revelaria um salt fixo, que embora não seja secreto, não há problema que esteja em claro. A estratégia exata depende da implementação).
- **Parâmetros do Argon2**: Possivelmente armazenados para saber com quais parâmetros a chave foi derivada (especialmente útil se no futuro quiserem suportar parâmetros variáveis ou outros KDFs). Poderia incluir t_cost, m_cost, etc., caso se queira permitir alteração desses valores por volume.
- **Tamanho do Volume**: Tamanho total do arquivo container ou do espaço de dados do volume externo.
- **Tamanho do Volume Oculto**: Se um volume oculto foi criado, seu tamanho ou offset inicial pode ser armazenado. Alguns designs evitam colocar explicitamente o tamanho do volume oculto no cabeçalho externo, para que um invasor com acesso ao cabeçalho externo não descubra que há “espaço reservado”. No CryptGuard, essa informação poderia estar apenas no cabeçalho do volume oculto, não no externo.
- **Checksum/Assinatura**: Além do magic de identificação, pode haver um checksum ou HMAC dos demais campos para validar integridade do cabeçalho (com a chave derivada). Em modos autenticados, o próprio GCM/Poly1305 do cabeçalho pode garantir a integridade. De qualquer forma, é importante que qualquer alteração não autorizada no cabeçalho seja detectável (senão um invasor poderia adulterar parâmetros para tentar enfraquecer a derivação, por exemplo).
- **Chave Mestra Cifrada (opcional)**: Em algumas implementações, em vez de usar diretamente a chave derivada do Argon2 para cifrar os dados, gera-se uma chave mestra aleatória para o volume e a cifra-se com a chave derivada da senha, armazenando-a no cabeçalho. Isso permite trocar a senha sem recriptografar todo o volume – basta decifrar a chave mestra com a senha antiga e recifrá-la com a nova. Não está claro se o CryptGuard segue esse modelo; caso não, a chave derivada do Argon2 *é* a chave de dados. Se sim, o cabeçalho conterá a chave mestra cifrada (e Argon2 serve apenas para desbloqueá-la).
- **Outros Campos**: Poderia haver indicadores como “tem volume oculto (bool)” ou padding para completar tamanho fixo do header. Entretanto, um indicador explícito de volume oculto poderia comprometer a negação plausível se um invasor ler o cabeçalho externo e ver flag de “hidden volume: true”. Por isso, é provável que o cabeçalho do volume externo **não contenha nenhuma referência explícita** ao oculto. O volume oculto teria seu próprio cabeçalho separado contendo seus parâmetros (similar ao do externo, mas talvez sem um campo de “hidden volume”).

*Como funciona:* Geralmente `metadata.py` define uma classe ou estrutura e métodos para (de)serializar os metadados para bytes. Por exemplo, `Metadata.to_bytes()` para produzir um bloco binário do tamanho fixo do header pronto para criptografar/escrever, e `Metadata.from_bytes(data: bytes)` para interpretar um bloco binário lido/decifrado do arquivo em um objeto Python com campos acessíveis. Quando se cria um volume novo, o CryptGuard monta um objeto de metadados preenchendo os campos (gera salt, define parâmetros, etc.), serializa em bytes e então cifra esse header com a chave derivada antes de escrever no início do arquivo. Quando se abre um volume, o processo inverso ocorre: lê-se os bytes iniciais do arquivo (do tamanho do header), tenta-se decifrar com a chave derivada da senha fornecida; se obtiver um resultado coerente (ex.: campo `magic` correto), então faz `Metadata.from_bytes` para carregar os campos e usa essas informações para prosseguir (p.ex., sabe-se onde começa/termina o volume oculto, quais parâmetros de Argon2 usar, etc.).

*Exemplo de uso:* Em geral, `metadata.py` é usado internamente pelo sistema e não diretamente chamado pelo usuário final. Mas um desenvolvedor, ao modificar ou inspecionar, poderia fazer algo como:
```python
from cryptguard.metadata import VolumeMetadata
meta = VolumeMetadata(
    salt=os.urandom(config.SALT_SIZE),
    has_hidden=True,
    hidden_size=1024*1024*100,  # 100 MB de volume oculto
    argon_params={'t_cost': 3, 'm_cost': 2**16, 'parallelism': 4},
    version=1
)
header_bytes = meta.to_bytes()
# ... cifra header_bytes com chave derivada e grava no arquivo ...
```
E para ler:
```python
# decifrar first_header_bytes com chave derivada da senha fornecida...
plaintext_header = cipher.decrypt(first_header_bytes)
meta = VolumeMetadata.from_bytes(plaintext_header)
print("Salt:", meta.salt, "Hidden volume?", meta.has_hidden)
```
Novamente, muitos detalhes exatos dependem da implementação, mas a ideia é que o módulo facilita o manuseio do header sem que outros componentes tenham que lidar com offsets e estruturas binárias manualmente.

*Como modificar:* Se for necessário adicionar informações extras no cabeçalho (por exemplo, um novo campo de configuração, ou suporte a múltiplos volumes ocultos), este módulo deve ser alterado. Ao fazê-lo, tome cuidado com o tamanho fixo do cabeçalho – ao mudar campos, a classe deve continuar serializando para o mesmo tamanho ou a versão do formato deve ser incrementada e lida condicionalmente. Por exemplo, para incluir um campo de “data de criação” ou “algoritmo de cifra utilizado”, pode-se usar algum espaço reservado ou expandir o header se possível. Lembre-se de atualizar a lógica de `to_bytes`/`from_bytes` e de validar essas informações durante a montagem. **Nunca armazene informações sensíveis em texto claro no cabeçalho** (exceto o salt que não é secreto), pois o cabeçalho pode ficar exposto se o adversário tiver o arquivo. Qualquer dado crítico deve estar cifrado ou derivado de forma a não revelar nada (por exemplo, se incluir um campo "has_hidden", talvez codificar de forma indireta ou omitir no externo). Considere também efeitos em compatibilidade: volumes antigos sem o novo campo ainda devem ser legíveis (talvez inferindo valores padrão para campos faltantes). Em resumo, `metadata.py` é central para a definição do formato do container – modifique-o com atenção redobrada, pois erros aqui podem tornar volumes inacessíveis.

### hidden_volume.py – Gerenciamento de Volume Oculto

Este módulo implementa a funcionalidade de criar e manipular volumes ocultos dentro de um container. Ele orquestra chamadas para outros módulos (metadata, chunk_crypto, argon_utils) para realizar operações complexas envolvendo dois conjuntos de dados (externo e oculto). As principais funções e comportamentos esperados em `hidden_volume.py` incluem:

- **Criação de Volume (Init)**: Uma função como `create_volume(caminho_arquivo, senha_externa, senha_oculta=None, tamanho_oculto=0, dados_externos=None)`. Essa função seria responsável por criar um novo arquivo container criptografado. Passos típicos:
  1. **Preparação do Arquivo**: Abre um novo arquivo no `caminho_arquivo` e define seu tamanho total. Se um volume oculto será criado (`senha_oculta` fornecida e `tamanho_oculto > 0`), o tamanho total do arquivo deverá acomodar tanto o volume externo quanto o oculto. Por exemplo, se o usuário quer um oculto de 100 MB dentro de um container de 500 MB, o arquivo terá 500 MB no total; o volume externo poderá ocupar até 400 MB e 100 MB estarão reservados para o oculto.
  2. **Preenchimento Inicial**: Escreve dados aleatórios em todo o arquivo (ou pelo menos nas áreas previstas para o volume oculto). Isso assegura que mesmo partes não utilizadas do volume tenham aparência aleatória indistinguível de dados cifrados reais. Essa etapa utiliza funções de geração aleatória (de utils) para produzir blocos e grava no arquivo repetidamente.
  3. **Configuração do Volume Externo**: Gera salt do Argon2, deriva a chave da senha externa. Monta os metadados do volume externo (via `metadata.py`), indicando possivelmente o espaço total do volume externo (que seria o total menos o espaço reservado ao oculto). Se um volume oculto será criado, pode ou não haver indicação nos metadados externos; idealmente, não explícita (o volume externo pode simplesmente ser tratado como menor do que o arquivo total, sem justificar por quê – do ponto de vista do invasor, o restante é espaço livre aleatório).
  4. **Criação do Volume Oculto (opcional)**: Se solicitado, similarmente gera salt e deriva chave para a senha oculta. Monta metadados para o volume oculto, indicando seu tamanho e talvez sua posição. A posição do volume oculto normalmente começa em algum offset dentro do arquivo. Uma estratégia comum: alocar o volume oculto no final do arquivo container. Ex: tamanho total 500 MB, volume oculto 100 MB começaria no offset 400 MB. Assim, o cabeçalho do volume oculto poderia ser armazenado logo no início dessa região (offset 400 MB do arquivo).
  5. **Escrita de Cabeçalhos**: Cifra e escreve o cabeçalho do volume externo no início do arquivo. Se há volume oculto, cifra e escreve seu cabeçalho em sua região designada (por exemplo, no início do espaço oculto, ou no final do arquivo – alguns designs colocam o cabeçalho do oculto no final do arquivo em vez de início da região, para maior discrição). 
  6. **Dados Iniciais**: Se `dados_externos` foram fornecidos (o usuário quer já colocar alguns arquivos no volume externo durante criação), o módulo poderia cifrá-los e armazená-los imediatamente após o cabeçalho externo. Entretanto, como geralmente o volume externo seria montado depois para gravação, o CryptGuard pode simplesmente criar o volume vazio (apenas com cabeçalhos e preenchimento aleatório). O mesmo vale para dados ocultos iniciais – normalmente, o volume oculto começa vazio.
  
- **Abertura/Montagem de Volume**: Função como `open_volume(caminho_arquivo, senha) -> ObjetoVolume`. Aqui o módulo decide, com base na senha fornecida, qual volume está sendo acessado:
  1. Lê o cabeçalho externo cifrado do início do arquivo e tenta decifrá-lo usando a senha (derivando chave via Argon2 e decifrando).
  2. Se a decifração produz metadados válidos (magic correto, versão conhecida, etc.), então a senha corresponde ao volume externo. O módulo então retornaria uma representação do volume externo (por exemplo, um objeto contendo a chave derivada e limites de espaço). Esse objeto pode ser usado com `streaming.py` para ler/escrever dados no volume externo.
  3. Se a senha falhou para o volume externo (metadados ilógicos), o módulo então tenta ler o cabeçalho do volume oculto (no offset onde ele supostamente estaria, como último 512 bytes do arquivo ou similar). Tenta decifrá-lo com a chave derivada da senha. Se obtiver metadados válidos, então a senha corresponde ao volume oculto. Retorna um objeto representando o volume oculto.
  4. Se nenhuma tentativa deu certo, a senha é inválida ou o arquivo não é um container CryptGuard.
  
  Esse fluxo implica que o módulo `hidden_volume.py` sabe onde procurar o cabeçalho do volume oculto. Essa informação poderia ser fixa (por exemplo, último setor do arquivo é sempre o header do oculto) ou derivada do tamanho total menos tamanho do header (se assumirmos o oculto ocupa final e seu header está logo no início do oculto). Outra possibilidade: armazenar dois headers consecutivos no início, um para externo e um para oculto, e distinguir pela tentativa de senha. Mas isso facilitaria detectar que existem dois headers. Provavelmente o design escolhe posições distintas para manter a ocultação.
  
- **Leitura/Escrita de Dados**: Uma vez determinado qual volume (externo ou oculto) está ativo, o `hidden_volume.py` coordena as operações de I/O através do módulo de streaming ou single_shot:
  - Para leitura/escrita sequencial, usa `streaming.py` passando a posição inicial e tamanho do volume dentro do arquivo. Por exemplo, para volume externo pode começar logo após o cabeçalho externo até o início do oculto (ou até tamanho total se não há oculto). Para volume oculto, o streaming começaria no início da região oculta até o final do arquivo.
  - O módulo também pode fornecer métodos mais simples como `read_file` ou `write_file` que internamente usam streaming ou single_shot para operações completas em arquivos comuns. Assim, o desenvolvedor poderia pedir para extrair um arquivo do volume oculto diretamente fornecendo path externo e interno.
  
- **Proteção contra Sobrescrita**: Se o volume externo for montado com conhecimento da senha oculta, `hidden_volume.py` pode ativar proteção contra escrita em áreas ocultas. Isso poderia ser implementado checando, a cada escrita no externo via streaming, se o offset vai além do limite permitido (início do volume oculto). Caso tente, retornar erro ou truncar. Essa funcionalidade dependeria de o usuário fornecer também a senha oculta ao montar o externo (sinalizando que ele sabe da existência e quer proteger). Caso não implementado ainda, fica como melhoria.

*Exemplos de uso:* Suponha que um desenvolvedor queira criar um volume criptografado com volume oculto via código (sem usar a CLI). Eles poderiam fazer:

```python
from cryptguard import hidden_volume
# Criar um volume de 100 MiB com um volume oculto de 20 MiB dentro
hidden_volume.create_volume(
    "meu_container.dat",
    senha_externa="senha123",
    senha_oculta="segredo!",
    tamanho_oculto=20 * 1024 * 1024
)
```

Isso irá gerar o arquivo `meu_container.dat` de 100 MiB, com volume externo de ~80 MiB e um volume oculto de 20 MiB. Depois, para escrever dados no volume oculto:

```python
vol = hidden_volume.open_volume("meu_container.dat", senha="segredo!")  # abre volume oculto
# 'vol' poderia ser um objeto que fornece acesso, por exemplo:
vol.write(b"mensagem secreta", path_in_volume="nota.txt")
vol.close()
```

Ou, usando streaming manualmente:

```python
# Abrir volume oculto e obter limites para streaming
vol = hidden_volume.open_volume("meu_container.dat", senha="segredo!")
start, length = vol.data_offset, vol.data_size  # posição e tamanho do volume oculto dentro do arquivo
with open("meu_container.dat", "rb") as container:
    container.seek(start)
    ciphertext = container.read(length)
# (Então decifrar ciphertext com vol.key usando streaming.decrypt_stream ou similar)
```

Do lado do volume externo:

```python
vol_ext = hidden_volume.open_volume("meu_container.dat", senha="senha123")
# Escrever dados no volume externo (até o limite de 80 MiB, sem tocar o oculto)
vol_ext.write_file("documento.txt", data=b"arquivo externo")
```

Os detalhes de API exata variam, mas essencialmente `hidden_volume.py` fornece essas operações de alto nível para que o restante da aplicação (ou CLI em `main.py`) possa criar e acessar volumes sem se preocupar com offsets e derivação de chaves a cada vez (isso fica encapsulado quando você obtém o objeto de volume com a chave pronta).

*Como modificar:* Alterações neste módulo devem ser feitas com extremo cuidado, pois é o coração da lógica de volumes ocultos:
- **Novos recursos**: Se quiser suportar múltiplos volumes ocultos (mais de um volume escondido com senhas diferentes dentro do mesmo container), este é o módulo a estender. Teria que definir como organizar vários volumes (por exemplo, dividir o espaço livre em várias partes, com múltiplos cabeçalhos ocultos). A lógica de abertura também teria que tentar várias posições de cabeçalho oculto para diferentes senhas.
- **Mudança na estratégia de alocação**: Por padrão, pode estar usando o final do arquivo para o volume oculto. Um desenvolvedor poderia optar por embutir o volume oculto em outra posição (por exemplo, logo após o cabeçalho externo, preenchendo o meio do arquivo com o oculto, e deixando o restante para externo). Isso exigiria recalcular offsets e talvez armazenar alguns indicadores (o que complica a negação plausível). Qualquer mudança assim deve manter o princípio de que sem a senha oculta é impossível distinguir espaços.
- **Proteção de volume oculto**: Implementar a funcionalidade de proteger o volume oculto contra sobrescrita quando montado o externo. Isso envolveria possivelmente solicitar as duas senhas juntas e marcar o objeto do volume externo com o limite protegido. Uma vez ativado, operações de escrita devem referenciar esse limite. Adicionar essa capacidade melhoraria a segurança ao usar ativamente os volumes, e pode ser introduzida aqui.
- **Performance**: Se for necessário melhorar desempenho ao acessar volumes, desenvolvedores podem introduzir cache de chave (se Argon2 for muito lento, talvez armazenar a chave derivada em memória durante uso prolongado, embora sempre derivar a chave na abertura seja mais seguro para não deixar em RAM por muito tempo). Podem também otimizar a cópia de dados aleatórios usando blocos maiores ou threads durante criação do volume.
- **Limpeza Segura**: Ao fechar um volume, pode ser prudente limpar (zerar) da memória qualquer chave ou senha mantida. Verifique se o módulo já o faz; caso contrário, considere adicionar para não deixar dados sensíveis em variáveis residuais.
  
Em resumo, `hidden_volume.py` coordena as operações de alto nível envolvendo dois conjuntos de dados criptografados no mesmo arquivo. Modificações aqui devem ser acompanhadas de testes extensivos: criar volumes, abrir com senhas corretas e incorretas, garantir que o volume oculto não seja detectável e que não haja vazamento de informações (por exemplo, tempo de resposta diferente se existe ou não oculto). Qualquer novo recurso no âmbito de volumes ocultos passa por este módulo.

### streaming.py – Criptografia em Streaming

O `streaming.py` é responsável por permitir a leitura e escrita de dados criptografados de forma contínua (stream), ao invés de carregar tudo na memória. Esse módulo é útil para trabalhar com arquivos grandes ou para integrar o CryptGuard em pipelines de dados (por exemplo, criptografar dados enquanto são transmitidos). Principais elementos de funcionamento:

- **Interface de Fluxo**: Pode definir classes ou funções geradoras. Por exemplo, uma classe `EncryptedWriter` que ao ser fornecida um arquivo de saída e a chave, oferece um método `write(plaintext_chunk)` que automaticamente cifra e grava no arquivo. Similarmente, um `EncryptedReader` que dado um arquivo cifrado e chave fornece `read()` retornando blocos de plaintext decifrados.
- **Uso de chunk_crypto**: Internamente, streaming.py utiliza as funções de `chunk_crypto.py`. Ele gerencia a iteração por blocos:
  - Lê X bytes do arquivo criptografado, chama `decrypt_chunk` e devolve ao consumidor.
  - Ou recebe X bytes de plaintext do produtor, chama `encrypt_chunk` e grava no arquivo de saída.
- **Manutenção de Estado**: Se um modo de cifra requer manter estado entre blocos (por exemplo, um CTR que incrementa o contador continuamente, ou manter o contexto do GCM se dividindo mensagens), a implementação terá que carregar esse contexto. Porém, geralmente `chunk_crypto.py` foi feito para blocos independentes com IVs calculáveis, então o `streaming.py` pode simplesmente iterar usando o índice do bloco para calcular IV ou recuperando do arquivo se armazenado.
- **Bufferização e Tamanho de Bloco**: O streaming possivelmente lê do arquivo cifrado em blocos do tamanho definido (ex.: 64KB). Pode usar um buffer interno para lidar com blocos parciais (no caso do último bloco que pode ser menor, ou se a leitura do consumidor não pede exatamente alinhado em blocos).
- **API de Alto Nível**: Além das classes geradoras, o módulo pode oferecer funções como `encrypt_stream(input_file, output_file, key)` e `decrypt_stream(input_file, output_file, key)` que leem do arquivo de entrada e escrevem no de saída completamente. Essas funções encapsulariam o loop de leitura e escrita de blocos, facilitando o uso.
- **Considerações de I/O**: Certifica-se de abrir arquivos binários no modo correto, tratar exceções de leitura/escrita (ex.: espaço em disco insuficiente, etc.), e fechar os arquivos ao final. Poderia também emitir progresso (não obrigatório, mas útil para grandes volumes; talvez não implementado por simplicidade, mas pode ser adicionado).

*Como funciona:* Supondo a existência de `encrypt_stream`, aqui está um possível fluxo:
```python
from cryptguard import streaming, chunk_crypto, argon_utils, metadata

# Parâmetros preparados: arquivo de entrada e saída, e a senha fornecida
with open("arquivo_claro.bin", "rb") as f_in, open("arquivo_cifrado.bin", "wb") as f_out:
    # Deriva chave (normalmente já teria sido feita antes e armazenada no metadata, 
    # mas se quisermos usar streaming isoladamente:)
    key = argon_utils.derive_key(password="minha_senha", salt=meu_salt)
    streaming.encrypt_stream(f_in, f_out, key)
# arquivo_cifrado.bin agora contém os dados criptografados em blocos sequenciais.
```
Dentro de `encrypt_stream`, o código faria algo como:
```python
def encrypt_stream(f_in, f_out, key):
    chunk_size = config.CHUNK_SIZE
    iv = inicializa_iv_inicial()  # definindo IV do primeiro bloco
    bloco_idx = 0
    while True:
        data = f_in.read(chunk_size)
        if not data: 
            break
        # se data menor que chunk_size, tratar padding ou anotar tamanho
        encrypted = chunk_crypto.encrypt_chunk(data, key, iv_for_index(bloco_idx))
        f_out.write(encrypted)
        bloco_idx += 1
```
A função `iv_for_index` pode estar em chunk_crypto ou calculada dentro de streaming: se o IV inicial é definido, e.g., como all-zero or derivado, e incrementa bloco_idx (para modos CTR/GCM isso pode ser concatenado com um contador, para XTS talvez calcula tweak etc., detalhes técnicos). Similar para decrypt_stream.

Para **leitura**:
```python
with open("arquivo_cifrado.bin", "rb") as f_in, open("arquivo_decifrado.bin", "wb") as f_out:
    key = argon_utils.derive_key(password="minha_senha", salt=meu_salt)
    streaming.decrypt_stream(f_in, f_out, key)
```
Onde `decrypt_stream` leria exatamente como foi escrito:
```python
def decrypt_stream(f_in, f_out, key):
    chunk_size = config.CHUNK_SIZE_on_disk  # possivelmente chunk_size + tag size if applicable
    bloco_idx = 0
    while True:
        encrypted = f_in.read(chunk_size_encrypted)
        if not encrypted:
            break
        plain = chunk_crypto.decrypt_chunk(encrypted, key, iv_for_index(bloco_idx))
        f_out.write(plain)
        bloco_idx += 1
```
Nota: se um modo autenticado (GCM) está em uso, o `chunk_crypto` pode incorporar verificação do tag dentro de decrypt_chunk e lançar exceção se inválido (indicando dados corrompidos ou senha errada). O streaming deve então interromper e repassar o erro adequadamente.

*Como modificar:* O `streaming.py` geralmente não precisa ser mudado a menos que:
- Mude a forma como os IVs são gerenciados (por exemplo, se trocar de AES-GCM para AES-CBC, o IV do próximo bloco deve ser o último bloco cifrado anterior – encadeamento – então streaming teria que carregar contexto ou passar o resultado de um bloco para o próximo).
- Suporte a **resumo/reinício**: talvez implementar a capacidade de retomar criptografia de um ponto específico do arquivo. Por exemplo, se quisermos acessar randomicamente um chunk específico, poderíamos expor uma função `decrypt_chunk_at(file, key, index)` usando streaming logicamente. Hoje pode não ser necessário, mas seria útil se implementar leitura aleatória dentro do volume.
- Adicionar **feedback de progresso**: se integrando em uma UI ou CLI, pode ser útil emitir quantos bytes já foram processados. Um desenvolvedor pode modificar o loop para invocar um callback ou imprimir algo a cada N MB processados.
- **Compressão**: não é função original deste módulo, mas um desenvolvedor poderia pensar em comprimir dados antes de criptografar para reduzir tamanho. Isso teria que ser feito aqui (ou em single_shot) antes de chamar chunk_crypto.
- **Parallelismo**: para melhorar velocidade em máquinas multi-core, poderia dividir o arquivo em regiões e processar múltiplos chunks em threads. Alterar streaming para isso é complexo e demandaria cuidado para não quebrar a ordem de escrita no arquivo de saída. Uma opção mais simples seria ler vários chunks e usar multiprocessing (mas Python GIL torna multi-thread CPU-bound não muito efetivo; multi-process seria pesado). Em todo caso, seria uma modificação profunda que requer sincronização e teste.
  
Mudar streaming sem necessidade não é comum; os desenvolvedores principalmente vão interagir com esse módulo para utilizá-lo. Se houver bugs na lógica de leitura/escrita (por exemplo, leitura do último bloco com padding), aí sim corrija-os aqui.

### single_shot.py – Operações de Uma Vez (One-shot encryption)

O `single_shot.py` fornece funções utilitárias para criptografar ou descriptografar dados em uma única chamada, isto é, carregando tudo em memória de uma vez em vez de usar streaming. Embora não seja eficiente para arquivos muito grandes, é útil para facilitar o uso em situações simples ou testes.

Prováveis funções aqui:
- `encrypt_file(input_path, output_path, password)` – abre um arquivo inteiro, lê todo conteúdo para a memória, deriva a chave, cifra todo o conteúdo (possivelmente ainda em blocos ou de uma vez só) e salva no arquivo de saída.
- `decrypt_file(input_path, output_path, password)` – análogo para decifrar tudo de uma vez.
- Talvez `encrypt_data(data_bytes, password) -> bytes` e `decrypt_data(data_bytes, password) -> bytes` – para uso programático direto em bytes já na memória, sem I/O de arquivo.

*Como funciona:* Esse módulo serve de fachada simples. Internamente, ele vai reusar componentes existentes:
- Para derivar a chave, chama `argon_utils.derive_key`.
- Para criptografar os dados, ele pode simplesmente usar `chunk_crypto.encrypt_chunk` numa só passada se os dados couberem em um chunk, ou dividir em vários chunks se muito grande. Porém, se fosse dividir em chunks, seria redundante dado que streaming já faz isso; é possível que single_shot simplesmente delegue para streaming mas lendo tudo de antemão.
- Outra abordagem é que single_shot defina o chunk size igual ao tamanho do dado, efetivamente cifrando tudo como um único bloco (mas aí deve gerenciar se dados > chunk_size normal).
- Após obter o dado cifrado, salva diretamente no output (ou retorna se for função *data*).
- Similarmente para decifrar: lê arquivo inteiro, passa para decrypt (com chave derivada), obtém plaintext, salva.

*Exemplo de uso:* 
```python
from cryptguard import single_shot

# Criptografar um arquivo de forma simples
single_shot.encrypt_file("segredo.txt", "segredo.cgd", password="minha_senha")

# Descriptografar
single_shot.decrypt_file("segredo.cgd", "segredo_decifrado.txt", password="minha_senha")

# Ou criptografar dados em memória
cipher_bytes = single_shot.encrypt_data(b"texto em memória", password="1234")
plain_bytes = single_shot.decrypt_data(cipher_bytes, password="1234")
```
Acima, `"segredo.cgd"` seria o arquivo criptografado (poderia ter extensão própria, `.cgd` aqui apenas ilustrativo). Repare que nessa interface simples não estamos lidando com volumes ocultos – é possivelmente apenas criptografia simples de um arquivo com uma senha. Pode ser útil quando o usuário não quer volume oculto e só deseja proteger um único arquivo de forma rápida.

*Como modificar:* Esse módulo é relativamente simples. Desenvolvedores podem:
- Adaptar para usar volumes ocultos se desejado. Por exemplo, poderia haver uma função `create_hidden_file(container_path, outer_password, hidden_password, data_outer, data_hidden)` que pega dois buffers e salva no container ambos (mas isso seria replicar parte de hidden_volume logic – talvez não seja necessário).
- Ajustar para operar com streams de bytes-like (por exemplo, receber um objeto file-like em vez de path).
- Melhorar uso de memória: se for extremamente grande, carregar tudo pode estourar a RAM. Poderia adaptar internamente para usar streaming e assim não explodir a memória. O nome "single shot" implicaria ler tudo, mas poderia ser implementado de forma híbrida (lê pedaços e cifra pedaços mas sem expor isso externamente).
- Se a lógica de chunk mudar (por exemplo, se passar a exigir tratar tags ou metadados diferentes), garantir que single_shot continue consistente com streaming e hidden_volume. No geral, single_shot deve produzir o mesmo resultado que streaming para o mesmo input, só que de forma síncrona. Testes devem comparar essas abordagens para garantir equivalência.
- Se não houver nada para mudar, esse módulo pode permanecer intocado; muitas modificações aqui seriam apenas chamadas de outros módulos, então mantenha-o atualizado caso as assinaturas de argon_utils ou chunk_crypto mudem.

### main.py – Interface de Linha de Comando e Inicialização

O `main.py` é o script que integra tudo e fornece a interface para o usuário final (normalmente via linha de comando). Esse módulo analisa argumentos, chama as funções adequadas dos outros módulos e lida com entradas/saídas básicas de usuário.

Possíveis funcionalidades implementadas em `main.py`:

- **Análise de Argumentos (CLI)**: Provavelmente usa a biblioteca `argparse` (ou similar) para definir opções e comandos. Exemplo de comandos que podem existir:
  - `cryptguard create -o <arquivo_container> -p <senha_externa> [-P <senha_oculta> -s <tamanho_oculto>]` – cria um novo volume, usando senha externa obrigatória e senha oculta/tamanho oculto opcionais.
  - `cryptguard open -o <arquivo_container> -p <senha> -d <diretorio_destino>` – abre um volume (externo ou oculto dependendo da senha) e **extrai** seu conteúdo para um diretório destino (se o CryptGuard suporta armazenar múltiplos arquivos ou se talvez considera o volume um disco virtual).
  - `cryptguard encrypt -i <arquivo_entrada> -o <arquivo_saida> -p <senha>` – modo simples de criptografar um arquivo (sem volume oculto, usando single_shot ou streaming).
  - `cryptguard decrypt -i <arquivo_entrada_cifrado> -o <arquivo_saida>` – decifrar arquivo simples (pede a senha via prompt ou argumento).
  
  Os nomes acima são hipotéticos, mas ilustram como main pode estruturar subcomandos para diferentes usos (criar volume, criptografar arquivo simples, etc.). Também trataria opções como verbose, ajuda, versão.
- **Interação com Usuário**: Para senhas, é importante não passá-las em texto claro via CLI (risco de ficarem no histórico ou visíveis em processos). `main.py` pode usar `getpass.getpass()` para solicitar senhas de forma oculta no terminal. Assim, mesmo que a opção `-p` exista, se não fornecida o programa pedirá interativamente.
- **Chamada de Módulos**: Com os argumentos interpretados, `main.py` invoca os módulos internos:
  - Se comando é `create`: chama `hidden_volume.create_volume` com os parâmetros fornecidos. Poderá construir também o conteúdo inicial do volume externo se usuário indicou algum arquivo a incluir.
  - Se comando é `encrypt`: decide se vai usar `single_shot.encrypt_file` (caso tamanho do arquivo seja pequeno ou por simplicidade) ou `streaming.encrypt_stream` (para arquivos maiores). Essa decisão pode ser manual (ex.: uma flag `--stream` para o usuário escolher) ou automática (por tamanho de arquivo).
  - Se comando é `open` ou `decrypt`: para volumes, chama `hidden_volume.open_volume` e depois talvez use `streaming` para copiar dados para fora; para arquivo simples, chama `single_shot.decrypt_file`.
  - Se comando for `add-hidden` (por exemplo, adicionar volume oculto a um container existente), main poderia abrir volume externo com ambas senhas e chamar alguma função para criar um oculto post facto (não sei se previsto, mas poderia).
- **Mensagens e Tratamento de Erros**: `main.py` deve fornecer feedback no console. Exemplos:
  - Mensagem de sucesso ao criar volume (e possivelmente instruções de uso).
  - Erro claro se a senha estiver errada ao tentar abrir (ex: "Senha incorreta ou volume inválido").
  - Avisos se tentar criar volume oculto maior que volume externo, etc.
  - Exibir ajuda se usar opções inválidas.
- **Inicialização**: Pode ser que `main.py` importe todos os módulos e inicie algo global (embora não muito necessário). Talvez definir logging básico ou verificar se o ambiente suporta certas coisas (ex: checar se módulo argon2 está disponível, caso tenha dependência externa).
- **Modo de Execução**: Comum ter:
  ```python
  if __name__ == "__main__":
      main()
  ```
  para permitir executar `python main.py ...` direto. A função `main()` interna seria onde argparse configura subcomandos e roteia para funções apropriadas.
  
*Exemplo de uso (CLI)*:  
No terminal, um usuário desenvolvedor ou final poderia fazer:
```
# Criar um container de 100 MB com 20 MB ocultos
$ python cryptguard/main.py create -o meucontainer.cgd --password-ext "senha123" --password-hidden "segredo!" --hidden-size 20
Volume criptografado criado com sucesso: meucontainer.cgd (Volume oculto de 20 MB incluído).

# Armazenar um arquivo no volume oculto:
$ python cryptguard/main.py open -o meucontainer.cgd --password "segredo!"
... (monta volume oculto em modo extração) ...
Copiando arquivos do volume oculto para ./volume_oculto_out/
```
Talvez o CryptGuard não implemente um sistema de arquivos completo; se for o caso, o comando `open` pode simplesmente decifrar todo o volume para um arquivo de saída se ele supõe que o volume contém apenas um fluxo de dados. Alternativamente, se definir que o container é como um drive, um possível aprimoramento é montar via FUSE, mas isso fugiria do escopo atual. O exemplo acima assume uma extração simples de conteúdo.

*Como modificar:* Desenvolvedores podem estender `main.py` para adicionar novos comandos ou alterar a forma de uso:
- **Novos subcomandos**: por exemplo, adicionar `change-password` (trocar a senha do volume). Isso exigiria ler o volume com a senha atual, recriptografar o cabeçalho com a nova senha e salvar. A implementação envolveria hidden_volume e metadata, mas a integração do comando seria aqui.
- **Integração com GUI**: Se planeja uma interface gráfica, `main.py` poderia ser adaptado para não usar argparse, mas ainda fornecer funções que a GUI chama. Alternativamente, separar a lógica CLI da lógica de negócio – já está modularizado, então a GUI pode chamar diretamente `hidden_volume` e outros sem passar por main.
- **Melhorias de usabilidade**: Por exemplo, permitir que o usuário não especifique `--hidden-size` e deduzir do tamanho atual do arquivo, ou um comando para listar informações do volume (não conteúdos, mas tamanho do oculto se souber senha).
- **Logging detalhado**: Durante desenvolvimento, pode ser útil ter uma opção de debug (`-v` ou `--verbose`) para imprimir passos internos (ex.: "Derivando chave com Argon2...", "Criando cabeçalho do volume externo...", etc.). `main.py` pode usar o módulo `logging` para isso. Desenvolvedores podem adicionar tais logs, garantindo que nada sensível (como senhas ou chaves brutas) seja impresso.
- **Validar entradas**: Adicionar checagens como tamanho oculto não pode ser >= tamanho total, senha não vazia, etc., com mensagens de erro claras.

No geral, `main.py` é o “colar” que junta tudo. Alterações nele são relativamente seguras (não afetam o núcleo criptográfico) desde que a lógica interna dos módulos seja usada corretamente. Ainda assim, teste qualquer novo fluxo de comandos para não introduzir cenários não suportados (por exemplo, tentar abrir um volume com senha oculta via comando errado).

## Considerações Finais

O CryptGuard apresenta uma base sólida para criptografia de volumes com ocultação, mas como todo projeto de segurança, requer manutenção cuidadosa e possibilidade de melhorias futuras:

- **Testes e Verificação**: É altamente recomendável implementar testes unitários e de integração para todos os módulos. Testes devem cobrir: criação de volume (verificar tamanho correto, impossibilidade de montar volume oculto sem senha correta), criptografia e descriptografia de arquivos (assegurar que o conteúdo original é recuperado bit a bit), manuseio de erros (senha errada não deve quebrar o programa, mas retornar erro claro), e cenários limite (volume oculto de tamanho zero, senhas iguais para externo e oculto, arquivos muito grandes, etc.). Antes de lançar modificações, valide contra essa suíte de testes para garantir que a segurança não foi regressiva.
- **Melhorias de Segurança**: Avalie adicionar camadas de segurança:
  - *Autenticidade dos Dados*: Se ainda não implementado, incluir verificação de integridade global do volume para detectar qualquer adulteração. Uma abordagem é armazenar um HMAC de todo o volume (ou de seções) usando uma chave derivada separada. Isso, porém, traz o desafio de onde armazenar o HMAC sem indicar a existência do oculto – possivelmente apenas proteger o volume externo e deixar o oculto implícito. Outra opção é usar sempre cifragem autenticada (como AES-GCM) por chunk, que já garante integridade local.
  - *Proteção de memória*: Garantir que senhas e chaves sejam apagadas da memória assim que possível. O Python não facilita controle fino de memória, mas práticas como sobrescrever variáveis com zeros e usar objetos de bytes imutáveis com cuidado podem ajudar. Analise pontos onde dados sensíveis ficam em memória e tente minimizar sua exposição (ex.: após derivar chave, não mantenha a senha em nenhuma variável).
  - *Números Aleatórios*: Verifique se todas as fontes de aleatoriedade usam um CSPRNG (gerador de números pseudoaleatórios criptograficamente seguro). Em Python, `os.urandom` ou `secrets` são adequados. Evite `random` do sistema (não é seguro para criptografia).
- **Documentação e Usabilidade**: Atualize a documentação de uso conforme novos recursos são adicionados. Por exemplo, se implementar change-password ou proteção de volume oculto, explique em README de usuário como usar. Do ponto de vista de desenvolvedor, mantenha comentários esclarecedores no código para as partes críticas (derivação de chave, estrutura de metadados, etc.). Isso facilita futuras manutenções por outros contribuidores.
- **Compatibilidade e Migração**: Se o projeto evoluir para versões subsequentes (v2, v3 do formato), planeje um esquema de versão e migração. O campo de versão nos metadados pode ser usado para que o código identifique volumes antigos e tente migrá-los (por exemplo, decifra com antigo método e reescreve cabeçalho no novo formato). Mantenha pelo menos capacidade de leitura de formatos antigos, ou forneça uma ferramenta de conversão.
- **Novas Funcionalidades**: Considere implementar:
  - Suporte a **diferentes algoritmos de cifragem** configuráveis (AES, ChaCha20, Twofish, etc.), possivelmente escolhíveis na criação do volume. Isso atrairia usuários com preferências específicas e serve de redundância caso um algoritmo seja comprometido no futuro.
  - **Compressão transparente** dos dados antes da criptografia para otimizar espaço, opcionalmente ativada por configuração.
  - **Montagem como unidade lógica**: Integrar com FUSE (em sistemas Unix) ou outras APIs para que o container CryptGuard possa ser montado como se fosse um disco, permitindo ao usuário interagir com arquivos e pastas normalmente dentro do volume. Isso é um projeto extenso à parte, mas aumentaria significativamente a usabilidade (tornando-o similar a TrueCrypt/VeraCrypt).
  - **Interface gráfica**: Criar uma GUI amigável que use os módulos internamente, para alcançar usuários não familiarizados com CLI. O design modular atual favorece isso, pois a lógica está separada do CLI.
- **Boas Práticas de Manutenção**: Ao modificar o código:
  - Siga um estilo consistente (PEP 8 para Python). Nomes de funções e variáveis devem ser claros e descritivos, especialmente em contexto de segurança.
  - Faça **code review** das mudanças focadas em segurança por pelo menos dois desenvolvedores, se possível. Bugs em código criptográfico podem ser sutis e ter grandes implicações.
  - Incremente gradativamente funcionalidades, testando cada adição em isolamento (por exemplo, ao trocar um algoritmo, primeiro teste manual de criptografia simples para verificar se os dados batem).
  - Mantenha as dependências (como bibliotecas de criptografia) atualizadas para receber patches de segurança, mas também monitore mudanças de API nelas ao atualizar.
  - Documente no README de desenvolvedor (este documento) quaisquer decisões de design importantes ou trade-offs, para que futuros mantenedores entendam o porquê das implementações atuais. Por exemplo: "optou-se por não armazenar flag de volume oculto no header externo para garantir negação plausível".

Em conclusão, o CryptGuard foi arquitetado com a separação clara de responsabilidades, o que deve facilitar a vida do desenvolvedor ao navegar e modificar o código. A implementação do volume oculto adiciona complexidade interessante, mas com a explicação acima, deve ficar mais claro onde cada parte acontece. Boa codificação!
