# crypto_core/single_shot.py
"""
Single-shot (non-streaming) encryption/decryption for smaller files,
agora com opção de dividir em sub-blocos e re-obfuscar a cada sub-bloco,
caso o arquivo supere config.SINGLE_SHOT_SUBCHUNK_SIZE.
"""

import os
import base64
import datetime
import secrets
import struct  # (usado na hora de salvar blocos chunked)
from typing import Optional

from crypto_core.argon_utils import get_argon2_parameters_for_encryption, generate_key_from_password
from crypto_core.chunk_crypto import encrypt_chunk, decrypt_chunk
from crypto_core.metadata import encrypt_meta_json, decrypt_meta_json
from crypto_core.secure_bytes import SecureBytes
from crypto_core import config
from crypto_core import utils  # para generate_unique_filename


def encrypt_data_single(data: bytes, 
                        password: SecureBytes,
                        file_type: str, 
                        original_ext: str = "",
                        key_file_hash: str = None, 
                        subchunk_size: Optional[int] = None):
    """
    Encrypt data in a single shot using Argon2id + ChaCha20Poly1305.

    Agora, se o 'data' for maior que 'subchunk_size', dividiremos em vários
    sub-blocos, re-obfuscando a chave a cada sub-bloco. Caso contrário,
    segue o fluxo tradicional de um único bloco.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError as e:
        print(f"Warning: Could not create output folder: {e}")

    # Parâmetros do Argon2
    argon_params = get_argon2_parameters_for_encryption()
    file_salt = secrets.token_bytes(32)

    if subchunk_size is None:
        subchunk_size = config.SINGLE_SHOT_SUBCHUNK_SIZE  # valor default

    data_len = len(data)
    try:
        derived_key_obf = generate_key_from_password(password, file_salt, argon_params)
    except MemoryError:
        print("MemoryError: Argon2 parameters might be too large for this system.")
        return

    # Esse 'aad_base' é usado em cada chunk
    aad_base = (f'{{"file_type":"{file_type}","original_ext":"{original_ext}",'
                f'"volume_type":"normal"}}').encode()

    # Se o arquivo for menor ou igual ao 'subchunk_size', 
    # faz como antes (um único chunk).
    if data_len <= subchunk_size:
        try:
            key_plain = derived_key_obf.deobfuscate()
            
            block = encrypt_chunk(data, key_plain, aad_base, 0)
            key_plain.clear()
            
            filename = utils.generate_unique_filename(file_type)
            enc_path = os.path.join(folder, filename)
            try:
                with open(enc_path, 'wb') as f:
                    f.write(block)
            except OSError as e:
                print(f"Erro ao gravar arquivo criptografado: {e}")
                return

            meta_plain = {
                "argon2_time_cost": argon_params["time_cost"],
                "argon2_memory_cost": argon_params["memory_cost"],
                "argon2_parallelism": argon_params["parallelism"],
                "salt": base64.b64encode(file_salt).decode(),
                "file_type": file_type,
                "original_ext": original_ext,
                "volume_type": "normal",
                "created_at": datetime.datetime.now().isoformat(),
                "use_rs": config.USE_RS,
                "version": config.META_VERSION,
                # Indica que não dividimos em múltiplos sub-blocos
                "multi_sub_block": False
            }
            if config.USE_RS:
                meta_plain["rs_parity"] = config.RS_PARITY_BYTES
            if key_file_hash:
                meta_plain["key_file_hash"] = key_file_hash

            if config.SIGN_METADATA:
                import hmac, hashlib
                temp_plain = derived_key_obf.deobfuscate()
                sig = hmac.new(bytes(temp_plain.to_bytes()), block, hashlib.sha256).hexdigest()
                meta_plain["signature"] = sig
                temp_plain.clear()

            meta_ok = encrypt_meta_json(enc_path + ".meta", meta_plain, password)
            if not meta_ok:
                print("Encryption failed during metadata writing.")
                try:
                    os.remove(enc_path)
                except OSError:
                    pass
                return

            print(f"\nEncrypted file saved as: {filename}")
        finally:
            derived_key_obf.clear()
            password.clear()

    else:
        # ---------------------------------------------
        # NOVO FLUXO: DIVIDINDO O 'data' EM SUB-BLOCOS
        # ---------------------------------------------
        try:
            filename = utils.generate_unique_filename(file_type)
            enc_path = os.path.join(folder, filename)

            encrypted_full = bytearray()
            
            offset = 0
            chunk_index = 0
            while offset < data_len:
                end = min(offset + subchunk_size, data_len)
                sub_data = data[offset:end]
                offset = end

                # Desobfusca a cada sub-bloco
                key_plain = derived_key_obf.deobfuscate()

                block = encrypt_chunk(sub_data, key_plain, aad_base, chunk_index)
                
                key_plain.clear()
                derived_key_obf.obfuscate()

                # Anexa ao grande buffer final
                encrypted_full.extend(block)
                chunk_index += 1

            # Salva tudo em um único arquivo
            try:
                with open(enc_path, 'wb') as f:
                    f.write(encrypted_full)
            except OSError as e:
                print(f"Erro ao gravar arquivo criptografado: {e}")
                return

            # Metadados, indicando que "multi_sub_block = True"
            meta_plain = {
                "argon2_time_cost": argon_params["time_cost"],
                "argon2_memory_cost": argon_params["memory_cost"],
                "argon2_parallelism": argon_params["parallelism"],
                "salt": base64.b64encode(file_salt).decode(),
                "file_type": file_type,
                "original_ext": original_ext,
                "volume_type": "normal",
                "created_at": datetime.datetime.now().isoformat(),
                "use_rs": config.USE_RS,
                "version": config.META_VERSION,
                # Indica que dividimos em múltiplos sub-blocos
                "multi_sub_block": True  
            }
            if config.USE_RS:
                meta_plain["rs_parity"] = config.RS_PARITY_BYTES
            if key_file_hash:
                meta_plain["key_file_hash"] = key_file_hash

            if config.SIGN_METADATA:
                import hmac, hashlib
                temp_plain = derived_key_obf.deobfuscate()
                sig = hmac.new(bytes(temp_plain.to_bytes()), encrypted_full, hashlib.sha256).hexdigest()
                meta_plain["signature"] = sig
                temp_plain.clear()

            meta_ok = encrypt_meta_json(enc_path + ".meta", meta_plain, password)
            if not meta_ok:
                print("Encryption failed during metadata writing.")
                try:
                    os.remove(enc_path)
                except OSError:
                    pass
                return

            print(f"\nEncrypted file (multi-chunk) saved as: {filename}")
        finally:
            derived_key_obf.clear()
            password.clear()


def decrypt_data_single(enc_path: str, password: SecureBytes):
    """
    Decrypts a single-shot encrypted file. 
    - Se o meta indicar 'multi_sub_block=False', faz a decifragem normal (um bloco só).
    - Se 'multi_sub_block=True', faz a decifragem em múltiplos blocos (semelhante ao streaming in-memory).
    """
    if not os.path.exists(enc_path + ".meta"):
        print("Warning: Metadata file not found. Cannot proceed with decryption.")
        password.clear()
        return

    meta_plain = decrypt_meta_json(enc_path + ".meta", password)
    if not meta_plain:
        print("Failed to decrypt metadata (incorrect password or corrupted data)!")
        password.clear()
        return

    old_use_rs = config.USE_RS
    old_rs_parity = config.RS_PARITY_BYTES
    config.USE_RS = meta_plain.get("use_rs", False)
    if "rs_parity" in meta_plain:
        config.RS_PARITY_BYTES = meta_plain["rs_parity"]
    
    derived_key_obf = None
    try:
        file_salt = base64.b64decode(meta_plain["salt"])
        argon_params = {
            "time_cost": meta_plain["argon2_time_cost"],
            "memory_cost": meta_plain["argon2_memory_cost"],
            "parallelism": meta_plain["argon2_parallelism"]
        }
        try:
            derived_key_obf = generate_key_from_password(password, file_salt, argon_params)
        except MemoryError:
            print("MemoryError: Argon2 parameters might be too large for this system.")
            return

        # Checa se esse arquivo foi gerado em modo multi_sub_block
        multi_sub_block = meta_plain.get("multi_sub_block", False)

        # Carrega o arquivo cifrado em RAM de uma vez
        # (o single-shot normalmente assume arquivos menores)
        try:
            with open(enc_path, 'rb') as f:
                file_data = f.read()
        except OSError as e:
            print(f"Error reading encrypted file: {e}")
            return

        # Se existir assinatura no metadata, verificamos antes de decifrar
        if "signature" in meta_plain:
            import hmac, hashlib
            temp_key_plain = derived_key_obf.deobfuscate()
            calc_sig = hmac.new(bytes(temp_key_plain.to_bytes()), file_data, hashlib.sha256).hexdigest()
            temp_key_plain.clear()
            if calc_sig != meta_plain["signature"]:
                print("Warning: encrypted file signature mismatch! Aborting decryption.")
                return

        # Monta o AAD 
        aad_base = (f'{{"file_type":"{meta_plain["file_type"]}",'
                    f'"original_ext":"{meta_plain["original_ext"]}",'
                    f'"volume_type":"{meta_plain["volume_type"]}"}}').encode()

        if not multi_sub_block:
            # Modo single-shot tradicional (um bloco só)
            key_plain = derived_key_obf.deobfuscate()
            plaintext, _ = decrypt_chunk(file_data, key_plain, 0, aad_base, 0)
            key_plain.clear()
            if plaintext is None:
                print("File decryption failed!")
                return

            # Salva o arquivo resultante
            folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
            try:
                os.makedirs(folder, exist_ok=True)
            except OSError as e:
                print(f"Warning: Could not create output folder: {e}")

            out_name = (f'decrypted_{meta_plain["file_type"]}_'
                        f'{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}_'
                        f'{secrets.token_hex(2)}'
                        f'{meta_plain.get("original_ext", "")}')
            out_path = os.path.join(folder, out_name)
            try:
                with open(out_path, 'wb') as f:
                    f.write(plaintext)
                print(f"\nDecrypted file saved as: {out_name}")
            except OSError as e:
                print(f"Error writing decrypted file: {e}")
            finally:
                try:
                    sec_plain = SecureBytes(plaintext)
                    sec_plain.clear()
                except Exception:
                    pass

        else:
            # ----------------------------
            # NOVO MODO: MULTI SUB-BLOCK
            # ----------------------------
            # Precisamos ler 'file_data' em vários blocos (cada um com 
            # 4 bytes de length + block data), semelhante ao streaming.

            offset = 0
            final_plain = bytearray()
            chunk_index = 0

            while True:
                if offset + 4 > len(file_data):
                    break  # chegou ao fim ou dados corrompidos
                block_len = struct.unpack('>I', file_data[offset:offset+4])[0]
                offset += 4

                if offset + block_len > len(file_data):
                    print("Corrupted file (incomplete block data)!")
                    return
                block_data = file_data[offset:offset+block_len]
                offset += block_len

                # Desobfuscar a chave, decifrar este bloco
                key_plain = derived_key_obf.deobfuscate()
                plaintext_chunk, _ = decrypt_chunk(
                    length_bytes = (struct.pack('>I', block_len) + block_data),
                    key=key_plain,
                    offset=0,
                    aad=aad_base,
                    chunk_index=chunk_index
                )
                key_plain.clear()
                derived_key_obf.obfuscate()

                if plaintext_chunk is None:
                    print("Decryption failed on a chunk!")
                    return

                final_plain.extend(plaintext_chunk)
                chunk_index += 1

            # Agora final_plain tem todos os dados
            folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
            try:
                os.makedirs(folder, exist_ok=True)
            except OSError as e:
                print(f"Warning: Could not create output folder: {e}")
            out_name = (f'decrypted_{meta_plain["file_type"]}_'
                        f'{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}_'
                        f'{secrets.token_hex(2)}'
                        f'{meta_plain.get("original_ext", "")}')
            out_path = os.path.join(folder, out_name)
            try:
                with open(out_path, 'wb') as f:
                    f.write(final_plain)
                print(f"\nDecrypted file (multi-chunk) saved as: {out_name}")
            except OSError as e:
                print(f"Error writing decrypted file: {e}")
            finally:
                try:
                    sec_plain = SecureBytes(final_plain)
                    sec_plain.clear()
                except Exception:
                    pass

    finally:
        config.USE_RS = old_use_rs
        config.RS_PARITY_BYTES = old_rs_parity
        
        if derived_key_obf is not None:
            derived_key_obf.clear()
        password.clear()
