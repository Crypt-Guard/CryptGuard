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
from .config           import SecurityProfile
from .aes_backends     import AesGcmCipher, AesCtrCipher
from .chacha_backends  import ChaChaCipher, XChaChaCipher

# ───────────────────────── mapa interno ───────────────────────────────────
# tag → (classe, streaming_default)
_CIPHER_MAP: dict[str, Tuple[Type, bool]] = {
    "AESG": (AesGcmCipher, False),      # AES‑GCM single‑shot por padrão
    "ACTR": (AesCtrCipher, False),
    "CH20": (ChaChaCipher, False),      # ChaCha single‑shot
    "CHS3": (ChaChaCipher, True),       # ChaCha streaming (8 MiB chunks)
    "XC20": (XChaChaCipher, False),     # XChaCha single‑shot
    "XCS3": (XChaChaCipher, True),      # XChaCha streaming
}

# Também aceitamos nomes “legíveis” como aliases para os tags de 4 chars
_ALIAS_TO_TAG: dict[str, str] = {
    "AES-256-GCM": "AESG",
    "AESG": "AESG",
    "AES-256-CTR": "ACTR",
    "ACTR": "ACTR",
    "CHACHA20-POLY1305": "CH20",
    "CH20": "CH20",
    "CHS3": "CHS3",
    "XCHACHA20-POLY1305": "XC20",
    "XC20": "XC20",
    "XCS3": "XCS3",
}

# ───────────────────────── helpers ────────────────────────────────────────

def get_cipher(algo: str, streaming: Optional[bool] = None) -> Type:
    """
    Resolve um alias/tag para a classe de cifra correspondente e define o
    valor padrão de streaming (_streaming_default) conforme o mapa ou o argumento.
    """
    if not algo:
        raise ValueError("Algoritmo não especificado")
    key = str(algo).upper()
    # Normaliza alias → tag de 4 chars
    tag = _ALIAS_TO_TAG.get(key, key if key in _CIPHER_MAP else None)
    if tag is None or tag not in _CIPHER_MAP:
        raise ValueError(f"Unsupported or unknown algorithm tag/alias: {algo!r}")
    cls, default_streaming = _CIPHER_MAP[tag]
    use_streaming = default_streaming if streaming is None else bool(streaming)
    # Evita mutar a classe original criando uma subclasse leve para carregar metadados
    CipherClass = type(f"{cls.__name__}Selected", (cls,), {})
    setattr(CipherClass, "_streaming_default", use_streaming)
    setattr(CipherClass, "_tag", tag)
    return CipherClass

def _resolve_enc_path(src: Path):
    # CG2-only: não há ZIP legado; manter assinatura por compat.
    return (src, None)

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
    original_path = Path(path)
    src, tmp_handle = _resolve_enc_path(original_path)

    # Lê somente o cabeçalho necessário (primeiros 24 bytes)
    with open(src, "rb") as f:
        head = f.read(24)
    if len(head) < 24:
        raise ValueError("Arquivo inválido ou corrompido: cabeçalho incompleto")

    tag_bytes = head[20:24]
    try:
        tag = tag_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError(f"Algoritmo desconhecido: {tag_bytes!r}")

    if tag not in _CIPHER_MAP:
        raise ValueError(f"Unsupported or unknown algorithm tag: {tag!r}")

    cipher = get_cipher(tag, streaming=kw.pop("streaming", None))

    # só mantemos parâmetros que decrypt_file realmente aceita
    if "profile_hint" not in kw:
        kw["profile_hint"] = SecurityProfile.BALANCED
    kw.pop("streaming", None)          # garante que não sobra ‘streaming’

    try:
        return cipher.decrypt_file(src, password, original_path=original_path, **kw)
    finally:
        tmp_handle = None  # noqa: F841

__all__ = ["get_cipher", "encrypt", "decrypt"]


# ───────────────────────── MIGRAÇÃO CG2 (overrides) ─────────────────────────
from .config import SecurityProfile, CG2_EXT
from .fileformat import is_cg2_file
from .cg2_ops import encrypt_to_cg2, decrypt_from_cg2

def encrypt(path: str | Path, password: str, algo: str = "AES-256-GCM", **kw) -> str:
    """Wrapper CG2 direto para cg2_ops.encrypt_to_cg2 (saída .cg2)."""
    profile = kw.pop("profile", SecurityProfile.BALANCED)
    exp_ts = kw.pop("expires_at", kw.pop("exp_ts", None))
    progress_cb = kw.pop("progress_cb", None)
    pad_block = kw.pop("pad_block", 0)

    # Normaliza alias/tag → nome aceito por cg2_ops
    alg_map = {
        "AESG":"AES-256-GCM","AES-256-GCM":"AES-256-GCM",
        "ACTR":"AES-256-CTR","AES-256-CTR":"AES-256-CTR",
        "CH20":"ChaCha20-Poly1305","CHACHA20-POLY1305":"ChaCha20-Poly1305",
        "XC20":"XChaCha20-Poly1305","XCHACHA20-POLY1305":"XChaCha20-Poly1305",
        "CHS3":"ChaCha20-Poly1305","XCS3":"XChaCha20-Poly1305",
    }
    alg_norm = alg_map.get((algo or "").upper(), algo)

    p = Path(path)
    outp = p.with_suffix(CG2_EXT)
    pwd = password.encode() if isinstance(password, str) else password
    result = encrypt_to_cg2(p, outp, pwd, alg_norm, profile, exp_ts, progress_cb=progress_cb, pad_block=pad_block)
    return str(result)

def decrypt(path: str | Path, password: str, **kw) -> str:
    """Wrapper CG2 direto para cg2_ops.decrypt_from_cg2 (autoextensão)."""
    progress_cb = kw.pop("progress_cb", None)

    p = Path(path)
    if not is_cg2_file(p):
        raise ValueError("Not a CG2 file")

    base = p.with_suffix("") if p.suffix.lower() == CG2_EXT else p.with_suffix(".dec")
    pwd = password.encode() if isinstance(password, str) else password
    result = decrypt_from_cg2(p, base, pwd, verify_only=False, progress_cb=progress_cb)
    return str(result)
