import sys
import os
import pytest
from pathlib import Path
from unittest.mock import patch, Mock, call

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core.safe_io import AtomicFileWriter, atomic_write_bytes

@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path

def test_atomic_file_writer_call_order(temp_dir):
    """Verifica se AtomicFileWriter chama flush, fsync, e rename na ordem correta."""
    file_path = temp_dir / "test_order.txt"
    test_data = b"ordem correta"

    mock_tmp_file = Mock()
    mock_tmp_file.name = str(temp_dir / "tempfile.tmp")

    # Mock das funções do SO para verificar a ordem
    with patch('tempfile.NamedTemporaryFile', return_value=mock_tmp_file):
        with patch('os.fsync') as mock_fsync:
            with patch('os.rename') as mock_rename:
                with AtomicFileWriter(file_path) as f:
                    f.write(test_data)

                # Verifica a ordem das chamadas
                expected_calls = [
                    call.write(test_data),
                    call.flush(),
                ]
                mock_tmp_file.assert_has_calls(expected_calls, any_order=False)
                mock_fsync.assert_called_once_with(mock_tmp_file.fileno())
                mock_rename.assert_called_once_with(Path(mock_tmp_file.name), file_path)
                mock_tmp_file.close.assert_called_once()

def test_atomic_write_bytes_writes_data(temp_dir):
    """Testa se atomic_write_bytes escreve os dados corretamente."""
    file_path = temp_dir / "test_bytes.txt"
    test_data = b"dados de teste"
    atomic_write_bytes(file_path, test_data)
    assert file_path.read_bytes() == test_data