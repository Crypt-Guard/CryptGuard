"""
CG2 operations – streaming com header autenticado (AAD), 4 algoritmos e proteção
contra truncamento + padding de tamanho + extensão original cifrada no rodapé.

Algoritmos:
  1) AES-256-GCM                 (nonce 12)
  2) XChaCha20-Poly1305          (nonce 24)  – via cryptography OU PyNaCl (fallback)
  3) ChaCha20-Poly1305 (IETF)    (nonce 12)
  4) AES-256-CTR + HMAC-SHA256   (IV 16)  → rodapé: [NAM0]* [SIZ0|8B] TAG0|32B

Payload framing (todos os modos):
  [ 4B big-endian (len_ct) | ct... ] * N

Footers:
  • AEAD: NAM0(opcional) | END0 | 4B (len_blob) | AESGCM(final_key).encrypt(nonce=0..0, payload=(chunks,total_pt), aad=header)
          (NAM0 é cifrado com chave derivada; END0 detecta truncamento e guarda tamanho real.)
  • CTR:  NAM0(opcional, autenticado na HMAC) | [SIZ0 | 8B total_pt] | TAG0 | 32B HMAC(header || Σ len||ct || [NAM0] || [SIZ0||total_pt])

Padding:
  - encrypt(): param opcional pad_block (int). Se >0, cada chunk é preenchido com zeros
    até múltiplo de pad_block. O tamanho real total_pt vai no footer e, na decriptação,
    o arquivo de saída é truncado para total_pt.

Progresso:
  - progress_cb(bytes_done) é chamado com bytes de plaintext processados (sem padding).
"""
from __future__ import annotations

import os
import struct
import time
import hmac as py_hmac
from pathlib import Path
from typing import Optional, Callable

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)
# XChaCha – cryptography (se disponível)
try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
    XCH_CRYPTO_AVAILABLE = True
except Exception:
    XChaCha20Poly1305 = None  # type: ignore
    XCH_CRYPTO_AVAILABLE = False

# Fallback PyNaCl (libsodium) para XChaCha
try:
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_encrypt as nacl_xch_encrypt,
        crypto_aead_xchacha20poly1305_ietf_decrypt as nacl_xch_decrypt,
    )
    NACL_XCH_AVAILABLE = True
except Exception:
    NACL_XCH_AVAILABLE = False

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .fileformat import CG2Header, read_header
from .kdf        import derive_key
from .config     import CG2_EXT, ARGON_PARAMS, SecurityProfile, CHUNK_SIZE
from .logger     import logger


AEAD_SET = {"AES-256-GCM", "XChaCha20-Poly1305", "ChaCha20-Poly1305"}

# ───────────────────────── constants / footers ──────────────────────────────
END_MAGIC  = b"END0"  # AEAD footer (final tag com chunks/total_pt)
TAG_MAGIC  = b"TAG0"  # CTR HMAC tag
SIZ_MAGIC  = b"SIZ0"  # CTR total_pt (opcional, antes do TAG0)
NAME_MAGIC = b"NAM0"  # bloco opcional com a extensão original cifrada

# ───────────────────────── helpers ──────────────────────────────────────────
def _derive_chunk_nonce(base: bytes, idx: int) -> bytes:
    """Deriva nonce único por chunk adicionando idx ao sufixo de 32 bits (mod 2^32)."""
    ctr = (int.from_bytes(base[-4:], "big") + idx) & 0xFFFFFFFF
    return base[:-4] + ctr.to_bytes(4, "big")


def _split_enc_mac_keys(mk: bytes) -> tuple[bytes, bytes]:
    """Para AES-CTR (+HMAC): deriva (enc_key, mac_key) via HKDF-SHA256."""
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"cg2-ctr-hkdf-v1").derive(mk)
    return okm[:32], okm[32:]


def _final_tag_key(mk: bytes) -> bytes:
    """Deriva chave para o footer AEAD (detecção de truncamento)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"cg2-final-tag-v1").derive(mk)


def _aead_final_tag(k: bytes, aad: bytes, chunk_count: int, total_pt: int) -> bytes:
    """
    MAC final para AEAD usando AESGCM, com nonce fixo 0..0 por arquivo.
    Retorna payload||tag, onde payload = struct(">IQ", chunks, total_pt).
    """
    nonce = b"\x00" * 12
    payload = struct.pack(">IQ", chunk_count, total_pt)
    return AESGCM(k).encrypt(nonce, payload, aad)


def _name_key(mk: bytes) -> bytes:
    """Chave para cifrar o bloco NAM0 (extensão original)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"cg2-name-v1").derive(mk)


def _pack_name_blob(k: bytes, aad: bytes, ext_text: str) -> bytes:
    """
    Produz: nonce(12) | 4B (len) | AESGCM(k).encrypt(nonce, ext_utf8, aad)
    """
    nonce = os.urandom(12)
    blob = AESGCM(k).encrypt(nonce, ext_text.encode("utf-8", "ignore"), aad)
    return nonce + struct.pack(">I", len(blob)) + blob


def _unpack_name_blob(k: bytes, aad: bytes, f) -> str:
    """
    Lê nonce(12) | 4B len | blob e retorna a extensão em texto.
    Levanta ValueError se truncado/inválido.
    """
    nonce = f.read(12)
    if len(nonce) != 12:
        raise ValueError("NAM0 truncado (nonce)")
    lb = f.read(4)
    if len(lb) != 4:
        raise ValueError("NAM0 truncado (len)")
    (blen,) = struct.unpack(">I", lb)
    blob = f.read(blen)
    if len(blob) != blen:
        raise ValueError("NAM0 truncado (blob)")
    pt = AESGCM(k).decrypt(nonce, blob, aad)
    return pt.decode("utf-8", "ignore")


def _pad(pt: bytes, block: int) -> bytes:
    """Padding com zeros até múltiplo de `block` (0 = sem padding)."""
    if block <= 0:
        return pt
    pad = (-len(pt)) % block
    if pad == 0:
        return pt
    return pt + (b"\x00" * pad)


def _guess_extension(first_bytes: bytes) -> str | None:
    """Detecção simples por magic bytes; retorna '.ext' ou None."""
    b = first_bytes
    b4 = b[:4] if len(b) >= 4 else b

    # imagens
    if b.startswith(b"\x89PNG\r\n\x1a\n"): return ".png"
    if b.startswith(b"\xff\xd8\xff"):      return ".jpg"
    if b.startswith(b"GIF87a") or b.startswith(b"GIF89a"): return ".gif"
    if len(b) >= 12 and b[:4] == b"RIFF" and b[8:12] == b"WEBP": return ".webp"
    if b.startswith(b"BM"): return ".bmp"

    # docs/arquivos
    if b4 == b"%PDF": return ".pdf"
    if b4 in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"): return ".zip"  # docx/xlsx também são zip
    if b.startswith(b"7z\xbc\xaf\x27\x1c"): return ".7z"
    if b4 == b"Rar!": return ".rar"
    if b4 == b"\x1f\x8b\x08": return ".gz"
    if len(b) >= 265 and b[257:262] == b"ustar": return ".tar"

    # audio/vídeo
    if b4 == b"ID3" or (len(b) > 1 and b[0] == 0xFF and (b[1] & 0xE0) == 0xE0): return ".mp3"
    if len(b) >= 12 and b4 == b"\x00\x00\x00\x18" and b[4:8] == b"ftyp": return ".mp4"
    if b4 == b"OggS": return ".ogg"
    if b4 == b"fLaC": return ".flac"

    # texto
    if b:
        printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in b[:256])
        if printable / max(1, len(b[:256])) > 0.95:
            return ".txt"

    return None


# ───────────────────────── API principal ────────────────────────────────────
def encrypt_to_cg2(
    in_path: str | Path,
    out_path: str | Path,
    password: bytes,
    alg: str,
    profile: SecurityProfile = SecurityProfile.BALANCED,
    exp_ts: int | None = None,
    *,
    progress_cb: Optional[Callable[[int], None]] = None,
    pad_block: int = 0,
) -> Path:
    """
    Criptografa em streaming para CG2 com header autenticado e rodapé.
    pad_block: se >0, aplica padding por chunk (zeros) até múltiplo de pad_block.
               O tamanho REAL (sem padding) é salvo no footer e restaurado no decrypt.
    """
    in_path  = Path(in_path)
    out_path = Path(out_path)
    if out_path.suffix.lower() != CG2_EXT:
        out_path = out_path.with_suffix(CG2_EXT)

    # KDF e chaves
    salt = os.urandom(16)
    kdf_params = {"name": "argon2id", "salt": salt.hex(), **ARGON_PARAMS[profile]}
    mk = derive_key(password, kdf_params)

    # Nonce/IV base
    if alg == "AES-256-GCM":
        base_nonce = os.urandom(12)
    elif alg == "XChaCha20-Poly1305":
        base_nonce = os.urandom(24)
    elif alg == "ChaCha20-Poly1305":
        base_nonce = os.urandom(12)
    elif alg == "AES-256-CTR":
        base_nonce = os.urandom(16)
    else:
        raise ValueError(f"Algoritmo não suportado: {alg}")

    # Header + AAD (sem extensão!)
    header = CG2Header(version=4, alg=alg, kdf=kdf_params, nonce=base_nonce, exp_ts=exp_ts)
    aad = header.pack()

    # Chaves
    if alg == "AES-256-CTR":
        enc_key, mac_key = _split_enc_mac_keys(mk)
    else:
        enc_key, mac_key = mk, None  # type: ignore

    total_real = 0  # bytes reais (sem padding)
    idx = 0

    with in_path.open("rb") as fin, out_path.open("wb") as fout:
        fout.write(aad)

        if alg in AEAD_SET:
            while True:
                pt = fin.read(CHUNK_SIZE)
                if not pt:
                    break
                total_real += len(pt)

                if pad_block:
                    pt = _pad(pt, pad_block)

                nonce = _derive_chunk_nonce(base_nonce, idx)
                if alg == "AES-256-GCM":
                    ct = AESGCM(enc_key).encrypt(nonce, pt, aad)
                elif alg == "XChaCha20-Poly1305":
                    if XCH_CRYPTO_AVAILABLE:
                        ct = XChaCha20Poly1305(enc_key).encrypt(nonce, pt, aad)
                    elif NACL_XCH_AVAILABLE:
                        ct = nacl_xch_encrypt(pt, aad, nonce, enc_key)
                    else:
                        raise RuntimeError("Backend XChaCha20 indisponível.")
                else:
                    ct = ChaCha20Poly1305(enc_key).encrypt(nonce, pt, aad)

                fout.write(struct.pack(">I", len(ct)))
                fout.write(ct)

                idx += 1
                if progress_cb:
                    progress_cb(total_real)

            # ── Rodapé AEAD ────────────────────────────────────────────
            # Escreve extensão original cifrada (opcional)
            name_k = _name_key(mk)
            ext_text = in_path.suffix or ""
            if ext_text:
                nb = _pack_name_blob(name_k, aad, ext_text)
                fout.write(NAME_MAGIC)
                fout.write(nb)

            # Footer AEAD (detecção de truncamento + tamanho real)
            ft_key = _final_tag_key(mk)
            final = _aead_final_tag(ft_key, aad, idx, total_real)  # payload||tag
            fout.write(END_MAGIC)
            fout.write(struct.pack(">I", len(final)))
            fout.write(final)

        else:
            # AES-CTR + HMAC (com tamanho real opcional)
            h = py_hmac.new(mac_key, digestmod="sha256")
            h.update(aad)

            while True:
                pt = fin.read(CHUNK_SIZE)
                if not pt:
                    break
                total_real += len(pt)

                if pad_block:
                    pt = _pad(pt, pad_block)

                iv = _derive_chunk_nonce(base_nonce, idx)
                cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv))
                enc = cipher.encryptor()
                ct = enc.update(pt) + enc.finalize()

                lb = struct.pack(">I", len(ct))
                fout.write(lb)
                fout.write(ct)

                h.update(lb)
                h.update(ct)

                idx += 1
                if progress_cb:
                    progress_cb(total_real)

            # ── Rodapé CTR ─────────────────────────────────────────────
            # NAM0 autenticado pela HMAC global (somente se houver extensão)
            name_k = _name_key(mk)
            ext_text = in_path.suffix or ""
            if ext_text:
                nb = _pack_name_blob(name_k, aad, ext_text)
                fout.write(NAME_MAGIC);  h.update(NAME_MAGIC)
                fout.write(nb);          h.update(nb)

            # tamanho real antes do TAG
            fout.write(SIZ_MAGIC)
            fout.write(struct.pack(">Q", total_real))
            h.update(SIZ_MAGIC)
            h.update(struct.pack(">Q", total_real))

            # TAG HMAC
            fout.write(TAG_MAGIC)
            fout.write(h.digest())

    logger.info("Encrypted CG2 %s → %s (%s, chunks=%d, real=%d)", in_path.name, out_path.name, alg, idx, total_real)
    return out_path


def decrypt_from_cg2(
    in_path: str | Path,
    out_path: str | Path,
    password: bytes,
    verify_only: bool = False,
    *,
    progress_cb: Optional[Callable[[int], None]] = None,
) -> Path | bool:
    """
    Descriptografa/verifica CG2 (streaming). Em AEAD, exige footer END0.
    Em CTR, aceita tanto formato novo (NAM0 + SIZ0 + TAG0) quanto legado (somente TAG0).
    Em ambos, se total_pt < bytes escritos (padding), o arquivo de saída é truncado.
    """
    in_path = Path(in_path)
    out_path = Path(out_path)

    hdr, aad, off, _ext_legacy_ignored = read_header(in_path)
    if hdr.exp_ts is not None and time.time() > hdr.exp_ts:
        raise PermissionError("File expired")

    mk = derive_key(password, hdr.kdf)
    if hdr.alg == "AES-256-CTR":
        enc_key, mac_key = _split_enc_mac_keys(mk)
    else:
        enc_key, mac_key = mk, None  # type: ignore

    total_written = 0  # bytes escritos no arquivo (pode incluir padding)
    idx = 0
    first_block = True
    out_f = None
    exp_total_from_footer: Optional[int] = None  # tamanho real (sem padding) vindo do rodapé
    ext_from_name: Optional[str] = None         # extensão original (NAM0), se existir

    def _ensure_open_with_ext_from(pt: bytes):
        nonlocal out_f, out_path
        if verify_only or out_f is not None:
            return
        # tentativa inicial por magic (será corrigido por NAM0 ao final)
        ext = _guess_extension(pt) or ""
        if out_path.suffix == "" and ext:
            out_path = out_path.with_suffix(ext)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_f = out_path.open("wb")

    with in_path.open("rb") as f:
        f.seek(off)
        try:
            if hdr.alg in AEAD_SET:
                # Loop de chunks
                while True:
                    len_bytes = f.read(4)
                    if not len_bytes:
                        # Agora exige footer:
                        raise ValueError("Footer ausente (arquivo possivelmente truncado)")

                    if len_bytes == NAME_MAGIC:
                        # ler extensão cifrada; não altera contagem de chunks
                        name_k = _name_key(mk)
                        ext_from_name = _unpack_name_blob(name_k, aad, f) or None
                        continue

                    if len_bytes == END_MAGIC:
                        # Checar footer AEAD
                        flen_b = f.read(4)
                        if len(flen_b) != 4:
                            raise ValueError("Footer truncado (len)")
                        (flen,) = struct.unpack(">I", flen_b)
                        blob = f.read(flen)
                        if len(blob) != flen:
                            raise ValueError("Footer truncado (blob)")

                        ft_key = _final_tag_key(mk)
                        nonce = b"\x00" * 12
                        payload = AESGCM(ft_key).decrypt(nonce, blob, aad)  # ValueError se inválido
                        exp_chunks, exp_total = struct.unpack(">IQ", payload)

                        if exp_chunks != idx or (not verify_only and exp_total > total_written):
                            raise ValueError("Footer inconsistente (contagem/tamanho)")

                        exp_total_from_footer = exp_total
                        # rejeita bytes extras após o rodapé
                        extra = f.read(1)
                        if extra:
                            raise ValueError("Dados extras após o rodapé (END0)")
                        break  # fim normal

                    # Caso comum: veio o tamanho do próximo chunk
                    (clen,) = struct.unpack(">I", len_bytes)
                    ct = f.read(clen)
                    if len(ct) != clen:
                        raise ValueError("Payload truncado/corrompido (AEAD)")

                    nonce = _derive_chunk_nonce(hdr.nonce, idx)
                    if hdr.alg == "AES-256-GCM":
                        pt = AESGCM(enc_key).decrypt(nonce, ct, aad)
                    elif hdr.alg == "XChaCha20-Poly1305":
                        if XCH_CRYPTO_AVAILABLE:
                            pt = XChaCha20Poly1305(enc_key).decrypt(nonce, ct, aad)
                        elif NACL_XCH_AVAILABLE:
                            pt = nacl_xch_decrypt(ct, aad, nonce, enc_key)
                        else:
                            raise RuntimeError("Backend XChaCha20 indisponível.")
                    else:
                        pt = ChaCha20Poly1305(enc_key).decrypt(nonce, ct, aad)

                    if first_block:
                        _ensure_open_with_ext_from(pt)
                        first_block = False

                    total_written += len(pt)
                    if progress_cb:
                        progress_cb(total_written)
                    if not verify_only:
                        if out_f is None:
                            _ensure_open_with_ext_from(pt)
                        out_f.write(pt)
                    idx += 1

                # fecha arquivo e trunca se necessário
                if not verify_only and out_f is not None and exp_total_from_footer is not None:
                    out_f.flush()
                    out_f.close()
                    if exp_total_from_footer < total_written:
                        with out_path.open("rb+") as tf:
                            tf.truncate(exp_total_from_footer)
                    out_f = None

            else:
                # CTR + HMAC
                h = py_hmac.new(mac_key, digestmod="sha256")
                h.update(aad)

                while True:
                    len_bytes = f.read(4)
                    if not len_bytes:
                        raise ValueError("TAG ausente no fim do arquivo (CTR)")

                    if len_bytes == NAME_MAGIC:
                        # NAM0 entra na HMAC exatamente como gravado
                        h.update(NAME_MAGIC)
                        name_k = _name_key(mk)
                        pos = f.tell()
                        nonce = f.read(12);  lb = f.read(4)
                        if len(nonce) != 12 or len(lb) != 4:
                            raise ValueError("NAM0 truncado (CTR)")
                        (blen,) = struct.unpack(">I", lb)
                        blob = f.read(blen)
                        if len(blob) != blen:
                            raise ValueError("NAM0 truncado (CTR)")
                        # Reprocessa com helper (sem reler do disco):
                        f.seek(pos)
                        ext_from_name = _unpack_name_blob(name_k, aad, f) or None
                        # Alimenta HMAC com bytes brutos
                        h.update(nonce); h.update(lb); h.update(blob)
                        continue

                    if len_bytes == SIZ_MAGIC:
                        # tamanho real (sem padding)
                        sz_b = f.read(8)
                        if len(sz_b) != 8:
                            raise ValueError("SIZ0 truncado (CTR)")
                        (exp_total_real,) = struct.unpack(">Q", sz_b)
                        h.update(SIZ_MAGIC); h.update(sz_b)
                        # Em seguida esperamos TAG0
                        next_magic = f.read(4)
                        if next_magic != TAG_MAGIC:
                            raise ValueError("TAG0 ausente após SIZ0 (CTR)")
                        tag = f.read(32)
                        if len(tag) != 32:
                            raise ValueError("TAG truncada (CTR)")
                        if not py_hmac.compare_digest(h.digest(), tag):
                            raise ValueError("HMAC inválido (arquivo corrompido ou senha incorreta)")
                        exp_total_from_footer = exp_total_real
                        # rejeita bytes extras após o TAG
                        extra = f.read(1)
                        if extra:
                            raise ValueError("Dados extras após o TAG0 (CTR)")
                        break

                    if len_bytes == TAG_MAGIC:
                        tag = f.read(32)
                        if len(tag) != 32:
                            raise ValueError("TAG truncada (CTR)")
                        if not py_hmac.compare_digest(h.digest(), tag):
                            raise ValueError("HMAC inválido (arquivo corrompido ou senha incorreta)")
                        # rejeita bytes extras após o TAG
                        extra = f.read(1)
                        if extra:
                            raise ValueError("Dados extras após o TAG0 (CTR)")
                        break

                    # Chunk normal
                    (clen,) = struct.unpack(">I", len_bytes)
                    ct = f.read(clen)
                    if len(ct) != clen:
                        raise ValueError("Payload truncado/corrompido (CTR)")

                    h.update(len_bytes)
                    h.update(ct)

                    iv = _derive_chunk_nonce(hdr.nonce, idx)
                    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv))
                    dec = cipher.decryptor()
                    pt = dec.update(ct) + dec.finalize()

                    if first_block:
                        _ensure_open_with_ext_from(pt)
                        first_block = False

                    total_written += len(pt)
                    if progress_cb:
                        progress_cb(total_written)
                    if not verify_only:
                        if out_f is None:
                            _ensure_open_with_ext_from(pt)
                        out_f.write(pt)
                    idx += 1

                # truncate pós-verificação (se soubermos o tamanho real)
                if not verify_only and out_f is not None:
                    out_f.flush()
                    out_f.close()
                    if exp_total_from_footer is not None and exp_total_from_footer < total_written:
                        with out_path.open("rb+") as tf:
                            tf.truncate(exp_total_from_footer)
                    out_f = None
        finally:
            # garante fechamento do arquivo de saída em caso de erro
            if not verify_only and out_f is not None and not out_f.closed:
                try:
                    out_f.close()
                except Exception:
                    pass

    # Renomeia a extensão final com base no NAM0, se houver (e se não for verify_only)
    if not verify_only and ext_from_name:
        want = ext_from_name if ext_from_name.startswith(".") else f".{ext_from_name}"
        cur = out_path.suffix
        if want and cur.lower() != want.lower():
            newp = out_path.with_suffix(want)
            try:
                os.replace(out_path, newp)
                out_path = newp
            except Exception:
                # se não der para renomear, mantém como está
                pass

    if verify_only:
        return True
    logger.info("Decrypted CG2 %s → %s (%s, chunks=%d)", in_path.name, out_path.name, hdr.alg, idx)
    return out_path
