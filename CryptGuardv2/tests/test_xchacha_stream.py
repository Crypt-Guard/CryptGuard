import sys
import os
import pytest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core.xchacha_stream import XChaChaStream
from crypto_core.fileformat_v5 import read_v5_header, V5Header

@pytest.fixture
def temp_files(tmp_path):
    in_file = tmp_path / "test_data.txt"
    in_file.write_bytes(os.urandom(1024)) # 1 KB
    out_file = tmp_path / "test_data.cg2"
    decrypted_file = tmp_path / "decrypted_data.txt"
    return in_file, out_file, decrypted_file

def test_read_v5_header_fails_on_truncated_file(temp_files):
    """Verifica que read_v5_header falha se o arquivo for menor que o header."""
    in_file, out_file, _ = temp_files
    password = "supersecretpassword"
    stream = XChaChaStream()

    encrypted_path_str = stream.encrypt_file(in_file, password, out_path=out_file)
    encrypted_path = Path(encrypted_path_str)

    # Trunca o arquivo para um tamanho muito pequeno
    with open(encrypted_path, "r+b") as f:
        f.truncate(10)

    with pytest.raises(ValueError, match="Truncated header"):
        read_v5_header(encrypted_path)

def test_full_encryption_decryption_roundtrip(temp_files):
    """Testa um ciclo completo de criptografia e descriptografia."""
    in_file, out_file, decrypted_file = temp_files
    password = "supersecretpassword"
    stream = XChaChaStream()

    original_data = in_file.read_bytes()

    encrypted_path_str = stream.encrypt_file(in_file, password, out_path=out_file)
    decrypted_path_str = stream.decrypt_file(encrypted_path_str, password, out_path=decrypted_file)

    assert decrypted_path_str is not None
    decrypted_data = Path(decrypted_path_str).read_bytes()
    assert decrypted_data == original_data