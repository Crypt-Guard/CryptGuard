# CryptGuard - Sistema de Criptografia Avançado

## 📌 Descrição
O **CryptGuard** é um sistema de criptografia avançado desenvolvido em Python, projetado para proteger arquivos, textos e volumes ocultos com técnicas de criptografia moderna e negação plausível. Ele utiliza **Argon2id** para derivação de chaves, **ChaCha20Poly1305** para criptografia autenticada e **Reed-Solomon** para correção de erros, garantindo alta segurança e integridade dos dados.

## 🚀 Funcionalidades
- 🔒 **Criptografia e descriptografia de arquivos e textos**
- 📂 **Criptografia em streaming para arquivos grandes**
- 📦 **Criação de volumes ocultos com negação plausível**
- 🔑 **Uso opcional de arquivos-chave para aumentar a segurança**
- ✅ **Correção de erros via Reed-Solomon para maior integridade**
- 🔐 **Metadados protegidos com criptografia**
- 🛠 **Configuração personalizada dos parâmetros de Argon2id**

## 🛠️ Tecnologias Utilizadas
- **Python 3.8+**
- `cryptography` (ChaCha20Poly1305)
- `argon2_cffi` (Argon2id)
- `reedsolo` (Correção de erros Reed-Solomon)
- `zxcvbn` (Validação da força da senha)

## 📥 Instalação
### Requisitos
Antes de executar o CryptGuard, certifique-se de ter o **Python 3.8+** instalado e instale as dependências:
```bash
pip install cryptography argon2-cffi reedsolo zxcvbn-python
```

### Clonando o Repositório
```bash
git clone https://github.com/seuusuario/CryptGuard.git
cd CryptGuard
```

## 🔧 Como Usar
O CryptGuard opera via linha de comando. Após instalar as dependências, execute o script principal:
```bash
python cryptguard.py
```

Você verá o seguinte menu:
```
=== CRYPTGUARD - SISTEMA DE CRIPTOGRAFIA AVANÇADO ===
[1] Criptografar Texto
[2] Criptografar Arquivo (Imagem/PDF/Áudio)
[3] Descriptografar Arquivo
[4] Criptografar Múltiplos Arquivos
[5] Gerar Token Efêmero
[6] Criar Volume Oculto (Negação Plausível)
[0] Sair
```
Basta escolher uma opção e seguir as instruções.

## 🛡️ Segurança
- **Recomenda-se usar senhas fortes** (mínimo 8 caracteres, com letras maiúsculas, minúsculas, números e caracteres especiais).
- **Arquivos-chave podem aumentar a entropia** e dificultar ataques de força bruta.
- **A negação plausível** é implementada no volume oculto, permitindo armazenar arquivos sigilosos de forma discreta.

## 📜 Licença
Este projeto está licenciado sob a **Apache License 2.0**. Consulte o arquivo `LICENSE` para mais detalhes.

## 🤝 Contribuição
Contribuições são bem-vindas! Para contribuir:
1. Faça um fork do projeto
2. Crie uma branch (`git checkout -b minha-feature`)
3. Faça suas alterações e commit (`git commit -m 'Minha nova feature'`)
4. Envie para o repositório (`git push origin minha-feature`)
5. Abra um **Pull Request**

## 📞 Contato
Se tiver dúvidas ou sugestões, entre em contato:
- **Email:** cryptguard737@gmail.com
- **GitHub:** [CryptGuard](https://github.com/Crypt-Guard)

---
🔐 *CryptGuard - Proteja seus dados com criptografia de alto nível!*
