# file_chooser.py

import tkinter as tk
from tkinter import filedialog

def select_file_for_encryption() -> str:
    """
    Abre uma janela de diálogo para escolher um único arquivo a ser criptografado.
    Retorna o caminho absoluto do arquivo selecionado ou uma string vazia se o usuário
    cancelar ou se ocorrer algum erro.
    """
    try:
        root = tk.Tk()
        root.withdraw()

        # Força a janela a ficar em primeiro plano
        root.attributes('-topmost', True)
        root.lift()
        root.focus_force()
        root.update()

        file_path = filedialog.askopenfilename(
            title="Selecione o arquivo para criptografar",
            filetypes=[("Todos os arquivos", "*.*")]
        )

        root.destroy()

        return file_path if file_path else ""
    except Exception:
        return ""

def select_files_for_decryption() -> tuple:
    """
    Abre uma janela de diálogo para escolher um ou mais arquivos relacionados à descriptografia.
    Retorna uma tupla (file1, file2). Se o usuário cancelar ou ocorrer algum erro, retorna (None, None).
    """
    try:
        root = tk.Tk()
        root.withdraw()

        # Força a janela a ficar em primeiro plano
        root.attributes('-topmost', True)
        root.lift()
        root.focus_force()
        root.update()

        files = filedialog.askopenfilenames(
            title="Selecione o(s) arquivo(s) para descriptografar (por ex., .enc e .meta)",
            filetypes=[
                ("Arquivos Encriptados", "*.enc"),
                ("Arquivos de Metadados", "*.meta"),
                ("Todos os arquivos", "*.*")
            ]
        )

        root.destroy()

        if not files:
            return None, None

        # Limitaremos a 2 arquivos para este exemplo
        file1 = files[0] if len(files) > 0 else None
        file2 = files[1] if len(files) > 1 else None

        return file1, file2
    except Exception:
        return None, None
