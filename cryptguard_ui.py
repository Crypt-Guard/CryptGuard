import flet as ft
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type
from reedsolo import RSCodec
import os
import base64
import secrets
from typing import Optional, Dict
from zxcvbn import zxcvbn
import json

# Paleta de cores inspirada nos apps da Meta
class Colors:
    PRIMARY = "#0866FF"  # Azul Meta
    SECONDARY = "#1C2B33"  # Cinza escuro
    BACKGROUND = "#FFFFFF"  # Branco
    SURFACE = "#F0F2F5"  # Cinza claro
    ERROR = "#FF4E4E"  # Vermelho
    SUCCESS = "#31A24C"  # Verde
    TEXT = "#1C2B33"  # Texto principal
    TEXT_SECONDARY = "#65676B"  # Texto secundário
    HOVER = "#E4E6E9"  # Cor de hover

class CryptGuardUI:
    def __init__(self):
        self.current_key: Optional[bytes] = None
        self.current_file: Optional[str] = None
        self.rs = RSCodec(32)
        self.action_type = "encrypt"  # ou "decrypt"
        self.password_field = None
        
        # Parâmetros default para Argon2id
        self.default_argon_params = {
            "time_cost": 4,
            "memory_cost": 102400,
            "parallelism": 2
        }
        self.current_argon_params = self.default_argon_params.copy()

    def main(self, page: ft.Page):
        self.page = page
        page.title = "CryptGuard"
        page.theme_mode = ft.ThemeMode.LIGHT
        page.padding = 20
        page.window_width = 1000
        page.window_height = 800
        page.window_resizable = True
        page.bgcolor = Colors.BACKGROUND
        page.scroll = ft.ScrollMode.AUTO

        # Criando o FilePicker
        self.file_picker = ft.FilePicker(
            on_result=self.handle_file_picked
        )
        page.overlay.append(self.file_picker)

        # Componentes da interface
        self.status_text = ft.Text(
            color=Colors.TEXT_SECONDARY,
            size=14,
            text_align=ft.TextAlign.CENTER,
        )

        # Arquivo selecionado
        self.selected_file_text = ft.Text(
            color=Colors.TEXT_SECONDARY,
            size=14,
            text_align=ft.TextAlign.CENTER,
        )

        title = ft.Text(
            "CryptGuard",
            size=40,
            weight=ft.FontWeight.BOLD,
            color=Colors.PRIMARY,
            text_align=ft.TextAlign.CENTER,
        )

        subtitle = ft.Text(
            "Proteja seus arquivos com criptografia avançada",
            size=16,
            color=Colors.TEXT_SECONDARY,
            text_align=ft.TextAlign.CENTER,
        )

        # Campo de senha com container estilizado
        self.password_field = ft.TextField(
            label="Senha",
            password=True,
            can_reveal_password=True,
            width=400,
            bgcolor=Colors.SURFACE,
            border_color=Colors.PRIMARY,
            label_style=ft.TextStyle(color=Colors.TEXT),
            on_change=self.check_password_strength,
            text_size=16,
        )

        password_container = ft.Container(
            content=ft.Column(
                controls=[
                    self.password_field,
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=10,
            border_radius=10,
        )

        # Indicador de força da senha
        self.password_strength = ft.Text(
            size=14,
            color=Colors.TEXT_SECONDARY,
            text_align=ft.TextAlign.CENTER,
        )

        # Configurações do Argon2id
        self.argon_config = ft.ExpansionTile(
            title=ft.Text(
                "Configurações Avançadas",
                size=16,
                weight=ft.FontWeight.BOLD,
            ),
            subtitle=ft.Text(
                "Parâmetros do Argon2id",
                size=14,
                color=Colors.TEXT_SECONDARY,
            ),
            controls=[
                ft.Container(
                    content=ft.Column(
                        controls=[
                            ft.TextField(
                                label="Time Cost (mínimo 3)",
                                value=str(self.current_argon_params["time_cost"]),
                                width=300,
                                text_size=16,
                                on_change=lambda e: self.update_argon_param("time_cost", e.control.value)
                            ),
                            ft.TextField(
                                label="Memory Cost em KiB (mínimo 65536)",
                                value=str(self.current_argon_params["memory_cost"]),
                                width=300,
                                text_size=16,
                                on_change=lambda e: self.update_argon_param("memory_cost", e.control.value)
                            ),
                            ft.TextField(
                                label="Parallelism (mínimo 2)",
                                value=str(self.current_argon_params["parallelism"]),
                                width=300,
                                text_size=16,
                                on_change=lambda e: self.update_argon_param("parallelism", e.control.value)
                            ),
                            ft.ElevatedButton(
                                text="Restaurar Padrões",
                                on_click=self.reset_argon_params,
                                style=ft.ButtonStyle(
                                    color=Colors.TEXT,
                                    bgcolor=Colors.SURFACE,
                                )
                            )
                        ],
                        spacing=20,
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    padding=20,
                    bgcolor=Colors.SURFACE,
                    border_radius=10,
                )
            ]
        )

        # Botões principais com hover effect
        self.encrypt_btn = ft.Container(
            content=ft.ElevatedButton(
                text="Criptografar Arquivo",
                icon=ft.Icons.LOCK,
                on_click=lambda _: self.start_encryption(),
                style=ft.ButtonStyle(
                    color=Colors.BACKGROUND,
                    bgcolor=Colors.PRIMARY,
                ),
                height=50,
            ),
            on_hover=lambda e: self.apply_hover_effect(e, self.encrypt_btn),
            animate=ft.animation.Animation(300, ft.AnimationCurve.EASE_IN_OUT),
        )

        self.decrypt_btn = ft.Container(
            content=ft.ElevatedButton(
                text="Descriptografar Arquivo",
                icon=ft.Icons.LOCK_OPEN,
                on_click=lambda _: self.start_decryption(),
                style=ft.ButtonStyle(
                    color=Colors.PRIMARY,
                    bgcolor=Colors.SURFACE,
                ),
                height=50,
            ),
            on_hover=lambda e: self.apply_hover_effect(e, self.decrypt_btn),
            animate=ft.animation.Animation(300, ft.AnimationCurve.EASE_IN_OUT),
        )

        # Layout principal
        page.add(
            ft.Column(
                controls=[
                    ft.Container(
                        content=ft.Column(
                            controls=[
                                title,
                                subtitle,
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=10,
                        ),
                        alignment=ft.alignment.center,
                        padding=ft.padding.only(bottom=40),
                        margin=ft.margin.only(top=20),
                    ),
                    ft.Container(
                        content=ft.Column(
                            controls=[
                                password_container,
                                self.password_strength,
                                self.selected_file_text,
                                ft.Row(
                                    controls=[
                                        self.encrypt_btn,
                                        self.decrypt_btn
                                    ],
                                    alignment=ft.MainAxisAlignment.CENTER,
                                    spacing=20
                                ),
                                self.argon_config,
                                self.status_text
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=20
                        ),
                        padding=40,
                        bgcolor=Colors.BACKGROUND,
                        border_radius=10,
                        shadow=ft.BoxShadow(
                            spread_radius=1,
                            blur_radius=10,
                            color="#1C2B3319"  # Cor com 10% de opacidade
                        )
                    )
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=20,
            )
        )

    def apply_hover_effect(self, e, button):
        """Aplica efeito de hover nos botões"""
        if e.data == "true":  # Mouse entrou
            button.scale = 1.02
            button.update()
        else:  # Mouse saiu
            button.scale = 1.0
            button.update()

    def check_password_strength(self, e):
        """Verifica e exibe a força da senha usando zxcvbn"""
        if not self.password_field.value:
            self.password_strength.value = ""
            self.password_strength.update()
            return

        result = zxcvbn(self.password_field.value)
        score = result["score"]
        
        strength_messages = {
            0: ("Muito fraca", Colors.ERROR),
            1: ("Fraca", Colors.ERROR),
            2: ("Média", "#FFA500"),  # Laranja
            3: ("Forte", "#2196F3"),  # Azul
            4: ("Muito forte", Colors.SUCCESS)
        }
        
        message, color = strength_messages[score]
        self.password_strength.value = f"Força da senha: {message}"
        self.password_strength.color = color
        self.password_strength.update()

    def update_argon_param(self, param: str, value: str):
        """Atualiza os parâmetros do Argon2id"""
        try:
            value = int(value)
            min_values = {
                "time_cost": 3,
                "memory_cost": 65536,
                "parallelism": 2
            }
            
            if value < min_values[param]:
                value = min_values[param]
                
            self.current_argon_params[param] = value
        except ValueError:
            self.show_error(f"Valor inválido para {param}")

    def reset_argon_params(self, e):
        """Restaura os parâmetros padrão do Argon2id"""
        self.current_argon_params = self.default_argon_params.copy()
        for control in self.argon_config.controls[0].content.controls:
            if isinstance(control, ft.TextField):
                param = control.label.split(" ")[0].lower() + "_cost"
                if param in self.current_argon_params:
                    control.value = str(self.current_argon_params[param])
                    control.update()
        self.show_success("Parâmetros restaurados para os valores padrão")

    def start_encryption(self):
        """Inicia o processo de criptografia"""
        self.action_type = "encrypt"
        self.file_picker.pick_files(
            allow_multiple=False,
            allowed_extensions=["*"]
        )

    def start_decryption(self):
        """Inicia o processo de descriptografia"""
        self.action_type = "decrypt"
        self.file_picker.pick_files(
            allow_multiple=False,
            allowed_extensions=["*"]
        )

    def handle_file_picked(self, e: ft.FilePickerResultEvent):
        if not e.files or len(e.files) == 0:
            return

        self.current_file = e.files[0].path
        self.selected_file_text.value = f"Arquivo selecionado: {os.path.basename(self.current_file)}"
        self.selected_file_text.update()

        if not self.password_field.value:
            self.show_error("Por favor, digite uma senha.")
            return

        if self.action_type == "encrypt":
            self.encrypt_file()
        else:
            self.decrypt_file()

    def generate_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Gera uma chave a partir da senha usando Argon2id"""
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=self.current_argon_params["time_cost"],
            memory_cost=self.current_argon_params["memory_cost"],
            parallelism=self.current_argon_params["parallelism"],
            hash_len=32,
            type=Type.ID
        )

    def encrypt_file(self):
        """Criptografa o arquivo selecionado"""
        if not self.current_file or not self.password_field.value:
            self.show_error("Por favor, selecione um arquivo e digite uma senha.")
            return

        try:
            # Gera salt aleatório
            salt = secrets.token_bytes(16)
            
            # Deriva a chave da senha
            key = self.generate_key_from_password(self.password_field.value, salt)
            
            # Cria o cipher
            cipher = ChaCha20Poly1305(key)
            nonce = secrets.token_bytes(12)

            # Lê o arquivo e criptografa
            with open(self.current_file, 'rb') as f:
                data = f.read()

            # Aplica Reed-Solomon no dados
            encoded_data = self.rs.encode(data)
            
            # Criptografa os dados
            ciphertext = cipher.encrypt(nonce, encoded_data, None)
            
            # Prepara os metadados
            metadata = {
                'salt': base64.b64encode(salt).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'argon_params': self.current_argon_params,
                'original_filename': os.path.basename(self.current_file),
                'original_extension': os.path.splitext(self.current_file)[1]
            }
            
            # Salva o arquivo criptografado
            output_file = f"{self.current_file}.encrypted"
            with open(output_file, 'wb') as f:
                # Salva os metadados
                f.write(base64.b64encode(json.dumps(metadata).encode()) + b'\n')
                # Salva o conteúdo criptografado
                f.write(ciphertext)

            self.show_success(f"Arquivo criptografado com sucesso: {os.path.basename(output_file)}")

        except Exception as e:
            self.show_error(f"Erro ao criptografar: {str(e)}")

    def decrypt_file(self):
        """Descriptografa o arquivo selecionado"""
        if not self.current_file or not self.password_field.value:
            self.show_error("Por favor, selecione um arquivo e digite a senha.")
            return

        try:
            with open(self.current_file, 'rb') as f:
                # Lê os metadados
                metadata = json.loads(base64.b64decode(f.readline().strip()).decode())
                # Lê o conteúdo criptografado
                ciphertext = f.read()

            # Recupera os parâmetros
            salt = base64.b64decode(metadata['salt'])
            nonce = base64.b64decode(metadata['nonce'])
            argon_params = metadata['argon_params']
            original_filename = metadata.get('original_filename', 'arquivo_descriptografado')
            original_extension = metadata.get('original_extension', '')

            # Atualiza os parâmetros do Argon2id para corresponder aos do arquivo
            self.current_argon_params = argon_params
            
            # Deriva a chave da senha
            key = self.generate_key_from_password(self.password_field.value, salt)
            
            # Cria o cipher
            cipher = ChaCha20Poly1305(key)

            try:
                # Descriptografa os dados
                decrypted_data = cipher.decrypt(nonce, ciphertext, None)
                
                # Aplica correção de erros Reed-Solomon
                decoded_data = self.rs.decode(decrypted_data)[0]
                
                # Salva o arquivo descriptografado com o nome original
                output_dir = os.path.dirname(self.current_file)
                base_name = os.path.splitext(original_filename)[0]
                
                # Garante um nome único para o arquivo
                output_file = os.path.join(output_dir, f"{base_name}{original_extension}")
                counter = 1
                while os.path.exists(output_file):
                    output_file = os.path.join(output_dir, f"{base_name}_{counter}{original_extension}")
                    counter += 1

                with open(output_file, 'wb') as f:
                    f.write(decoded_data)

                self.show_success(f"Arquivo descriptografado com sucesso: {os.path.basename(output_file)}")

            except InvalidTag:
                self.show_error("Senha incorreta ou arquivo corrompido.")
            except Exception as e:
                self.show_error(f"Erro ao descriptografar: {str(e)}")

        except Exception as e:
            self.show_error(f"Erro ao ler o arquivo: {str(e)}")

    def show_error(self, message: str):
        self.status_text.value = message
        self.status_text.color = Colors.ERROR
        self.status_text.update()

    def show_success(self, message: str):
        self.status_text.value = message
        self.status_text.color = Colors.SUCCESS
        self.status_text.update()

if __name__ == "__main__":
    app = CryptGuardUI()
    ft.app(target=app.main) 