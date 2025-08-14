from __future__ import annotations

import zipfile
from collections.abc import Iterable
from pathlib import Path


def pack_enc_zip(inputs: Iterable[str | Path], out_zip: str | Path,
                 password: str | bytes, *, algo: str = "AESG") -> str:
    out_zip = Path(out_zip)
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for item in inputs:
            p = Path(item)
            if p.is_dir():
                for f in p.rglob("*"):
                    if f.is_file():
                        z.write(f, f.name)
            elif p.is_file():
                z.write(p, p.name)
            else:
                raise FileNotFoundError(f"Entrada não encontrada: {p}")
    cg2_path = out_zip.with_suffix(".cg2")
    try:
        from CryptGuardv2.crypto_core.factories import encrypt  # type: ignore
        encrypt(str(out_zip), password, algo=algo, out_path=str(cg2_path))
    except Exception:
        try:
            from crypto_core.factories import encrypt  # type: ignore
            encrypt(str(out_zip), password, algo=algo, out_path=str(cg2_path))
        except Exception:
            from CryptGuardv2.crypto_core.cg2_ops import encrypt_to_cg2  # type: ignore
            alg_map = {"AESG": "AES-256-GCM", "ACTR": "AES-256-CTR", "XC20": "XChaCha20-Poly1305", "CH20": "ChaCha20-Poly1305"}
            pwd = password.encode() if isinstance(password, str) else password
            encrypt_to_cg2(str(out_zip), str(cg2_path), pwd, alg=alg_map.get(algo, algo))
    return str(cg2_path)
