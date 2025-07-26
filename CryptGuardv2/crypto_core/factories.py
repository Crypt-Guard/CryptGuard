"""factories.py – fábrica de ciphers para o CryptGuard v2

Uso típico (exportado por __init__.py):

```python
from .factories import get_cipher

cipher = get_cipher("AESG")      # AES‑256‑GCM (streaming automático)
cipher.encrypt_file("foo.bin", "senha_secreta")
```

A string pode vir do usuário ("AESG", "ACTR", "CH20", "CHS3", "XC20", "XCS3")
ou de um *magic tag* lido do cabeçalho (PATH.read_bytes()[20:24]).

• tags terminadas em **S3** ⇒ streaming=True por padrão.  
• Caso o chamador passe explicitamente `streaming=...` este valor sobrescreve.

A fábrica retorna simplesmente a *classe* adequada (subclasse de BaseCipher).
Isso permite chamar diretamente `encrypt_file()` / `decrypt_file()` sem
instanciação.
"""
from __future__ import annotations

from pathlib import Path
from typing import Tuple, Type, Optional
from .utils import unpack_enc_zip

from .config           import SecurityProfile
from .aes_backends     import AesGcmCipher, AesCtrCipher
from .chacha_backends  import ChaChaCipher, XChaChaCipher

# ───────────────────────── mapa interno ───────────────────────────────────
# tag → (classe, streaming_default)
_CIPHER_MAP: dict[str, Tuple[Type, bool]] = {
    "AESG": (AesGcmCipher, False),      # AES‑GCM single‑shot por padrão
    "ACTR": (AesCtrCipher, False),
    "CH20": (ChaChaCipher, False),      # ChaCha single‑shot
    "CHS3": (ChaChaCipher, True),       # ChaCha streaming (8 MiB chunks)
    "XC20": (XChaChaCipher, False),     # XChaCha single‑shot
    "XCS3": (XChaChaCipher, True),      # XChaCha streaming
}

# ───────────────────────── helpers ────────────────────────────────────────

def _resolve_enc_path(src: Path) -> Tuple[Path, Optional[object]]:
    """Retorna (caminho_do_.enc, handle_tmp) onde *handle_tmp* mantém vivo
    o diretório temporário criado por `unpack_enc_zip` (ou `None`)."""
    if src.suffix.lower() == ".zip":
        enc_path, tmp = unpack_enc_zip(src)
        return enc_path, tmp  # manter referência viva
    return src, None

# ───────────────────────── API pública ────────────────────────────────────

def get_cipher(tag: str, *, streaming: bool | None = None):
    """Resolve *tag* (4 chars) → classe de cipher.

    Args:
        tag: Identificador ASCII – e.g. "AESG", "CHS3".
        streaming: Forçar/desligar modo streaming.  `None` mantém default.

    Returns:
        Subclasse de BaseCipher pronta para uso.
    """
    tag = tag.upper()
    if tag not in _CIPHER_MAP:
        raise ValueError(f"Algoritmo desconhecido: {tag!r}")

    cls, default_stream = _CIPHER_MAP[tag]
    cls_default_stream = default_stream if streaming is None else streaming

    # Se usuário não especificou, attach atributo de conveniência
    cls._streaming_default = cls_default_stream  # type: ignore[attr-defined]
    return cls

def encrypt(path: str | Path, password: str, algo: str = "AESG", **kw) -> str:
    """Função helper exposta em `crypto_core.__init__`.

    Kwargs aceitos são encaminhados a `encrypt_file()` (profile, progress_cb…)
    """
    cipher = get_cipher(algo, streaming=kw.pop("streaming", None))
    if "profile" not in kw:
        kw["profile"] = SecurityProfile.BALANCED
    if "streaming" not in kw:
        kw["streaming"] = getattr(cipher, "_streaming_default", False)
    return cipher.encrypt_file(path, password, **kw)


def decrypt(path: str | Path, password: str, **kw) -> str:
    """
    Descriptografa *.enc* ou o *.zip* produzido por `pack_enc_zip`.
    Detecta algoritmo pelo cabeçalho do arquivo extraído.
    """
    original_path = Path(path)  # Save the user-provided path
    src, tmp_handle = _resolve_enc_path(original_path)

    tag_bytes = src.read_bytes()[20:24]
    try:
        tag = tag_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError(f"Algoritmo desconhecido: {tag_bytes!r}")

    # Strict tag check
    if tag not in _CIPHER_MAP:
        raise ValueError(f"Unsupported or unknown algorithm tag: {tag!r}")

    cipher = get_cipher(tag, streaming=kw.pop("streaming", None))

    # só mantemos parâmetros que decrypt_file realmente aceita
    if "profile_hint" not in kw:
        kw["profile_hint"] = SecurityProfile.BALANCED
    kw.pop("streaming", None)          # garante que não sobra ‘streaming’

    try:
        # Pass original_path to decrypt_file
        return cipher.decrypt_file(src, password, original_path=original_path, **kw)
    finally:
        # mantém `tmp_handle` vivo até aqui; depois sai do contexto e remove temp dir
        tmp_handle = None  # noqa: F841

__all__ = ["get_cipher", "encrypt", "decrypt"]
