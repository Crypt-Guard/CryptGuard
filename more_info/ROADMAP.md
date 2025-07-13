```markdown
# 🚀 CryptGuardv2 Roadmap

Este documento detalha as funcionalidades atuais e futuras planejadas para o **CryptGuardv2**, refletindo as grandes atualizações introduzidas nesta versão GUI avançada.

---

## 🔑 Funcionalidades Principais Atuais

| Status | Funcionalidade                                        | Detalhes                                  |
|--------|-------------------------------------------------------|-------------------------------------------|
| ✅      | **Criptografia/Descriptografia AES-256-GCM**         | Streaming e Single-shot para arquivos     |
| ✅      | **Criptografia/Descriptografia ChaCha20-Poly1305**   | Alternativa leve, single-shot e streaming |
| ✅      | **Argon2id (com calibração automática)**             | Derivação segura e resistente a GPUs      |
| ✅      | **HMAC-SHA256 Global**                               | Verificação de integridade completa       |
| ✅      | **Reed-Solomon opcional**                            | Recuperação limitada de corrupção leve    |
| ✅      | **Rate-Limiter local (protege contra força-bruta)**  | Atraso exponencial por tentativas falhas  |
| ✅      | **Proteção avançada em RAM**                         | Obfuscação XOR e VirtualLock              |
| ✅      | **Secure Delete (opcional)**                         | Exclusão segura após criptografia         |
| ✅      | **Interface gráfica moderna (PySide6)**              | Drag-and-drop, medidor de força de senha  |
| ✅      | **Logs detalhados**                                  | Auditoria facilitada                      |

---

## 🚧 Futuras Funcionalidades

| Prioridade | Funcionalidade                                   | Descrição                                       |
|------------|--------------------------------------------------|-------------------------------------------------|
| 🔶         | **Hidden Volumes**                               | Volumes ocultos com negação plausível           |
| 🔶         | **Key-Rolling GUI**                               | Troca segura da senha via GUI                   |
| 🔶         | **Ephemeral Tokens via GUI**                      | Gerador seguro de tokens de sessão              |
| 🔷         | **Multi-línguas (PT, EN, ES)**                    | Internacionalização da interface                |
| 🔷         | **Notificações de segurança integradas**          | Alertas críticos integrados ao sistema          |
| 🔷         | **Backup automático e criptografado**             | Backup automático periódico com criptografia    |

🔶 = Médio prazo, 🔷 = Longo prazo

---

## 🔐 Perfis de Segurança Configuráveis (Argon2id)

CryptGuardv2 utiliza perfis pré-definidos Argon2id para ajustar performance e segurança:

- **Ultra Rápido** (mínima segurança, máxima velocidade)
- **Balanceado (padrão)** (equilíbrio ideal entre segurança e performance)
- **Seguro** (máxima segurança, recomendado para arquivos sensíveis)

---

## 🛠 Manutenção e Versões

- **Versão atual**: **2.0 GUI**
  - Novo backend paralelo para arquivos grandes
  - GUI moderna e intuitiva usando PySide6
  - Melhorias substanciais de segurança e performance

- **Compatibilidade**:
  - Compatível com arquivos `.enc` das versões anteriores CLI v1.2.0+

---

## 🤝 Como Contribuir

Veja [CONTRIBUTING.md](CONTRIBUTING.md) para se envolver:
- Relate bugs e sugira funcionalidades via **Issues**.
- Submeta **Pull Requests** com melhorias diretas.
- Problemas de segurança: consulte [SECURITY.md](../SECURITY.md).

---

**Última atualização**: Julho de 2025  
© Equipe CryptGuard – Segurança digital ao seu alcance.
```
