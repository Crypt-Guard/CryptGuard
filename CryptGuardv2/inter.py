import sys
import qtawesome as qta  # Para ícones modernos
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QIcon, QPalette, QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QFormLayout, QLabel, QLineEdit, QPushButton,
    QComboBox, QCheckBox, QRadioButton, QProgressBar, QGroupBox,
    QDateEdit, QFrame, QScrollArea, QSizePolicy
)

# --- Estilo QSS (CSS do Qt) para o tema moderno ---
# ATUALIZADO para ser menos quadrado e mais minimalista, com transparência
MODERN_QSS = """
QWidget {
    background-color: #2E3440; /* Fundo principal (Nord Polar Night) */
    color: #ECEFF4; /* Texto principal (Nord Snow Storm) */
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 10pt;
}

/* --- Agrupamento (AGORA MINIMALISTA) --- */
QGroupBox {
    /* Removemos a "caixa" para um visual mais limpo */
    background-color: transparent;
    border: none; 
    margin-top: 20px;
    padding: 0;
}

QGroupBox::title {
    /* O título agora age como um cabeçalho de seção */
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0;
    margin-left: 0; /* Sem indentação */
    background-color: transparent;
    color: #88C0D0; /* Cor de destaque para títulos (Nord Frost) */
    font-size: 13pt; /* Fonte maior para destacar */
    font-weight: bold;
}

/* --- Widgets de Entrada (COM TRANSPARÊNCIA E MENOS QUADRADO) --- */
QLineEdit, QComboBox, QDateEdit {
    /* Efeito de vidro (rgba) e mais arredondado */
    background-color: rgba(59, 66, 82, 0.7); /* #3B4252 com 70% opacidade */
    border: 1px solid rgba(76, 86, 106, 0.7); /* #4C566A com 70% opacidade */
    border-radius: 10px; /* Mais arredondado */
    padding: 8px;
    color: #ECEFF4;
}

QLineEdit:focus, QComboBox:focus, QDateEdit:focus {
    border: 1px solid #88C0D0; /* Destaque ao focar */
}

/* --- Botões (MENOS QUADRADO) --- */
QPushButton {
    border: none;
    border-radius: 10px; /* Mais arredondado */
    padding: 8px 16px;
    font-weight: bold;
    color: #ECEFF4;
}

QPushButton:hover {
    background-color: #4C566A;
}

QPushButton:pressed {
    background-color: #434C5E;
}

/* Botão Primário (CTA - Call to Action) */
QPushButton#primaryButton {
    background-color: #5E81AC; /* Azul (Nord Frost) */
    color: #ECEFF4;
}
QPushButton#primaryButton:hover {
    background-color: #6a90c2;
}

/* Botão Secundário (Ações de Geração) */
QPushButton#secondaryButton {
    background-color: #81A1C1; /* Azul mais claro */
    color: #2E3440; /* Texto escuro para contraste */
}
QPushButton#secondaryButton:hover {
    background-color: #8fafcf;
}

/* Botões de Ação (MINIMALISTAS) */
QPushButton#actionButton {
    /* Fundo transparente por padrão (estilo "outline") */
    background-color: transparent;
    border: 1px solid #4C566A;
}
QPushButton#actionButton:hover {
    background-color: #4C566A;
    border-color: #4C566A;
}

/* Botões do Footer (Menos destaque) */
QPushButton#footerButton {
    background-color: transparent;
    color: #88C0D0;
    font-weight: normal;
    padding: 5px;
}
QPushButton#footerButton:hover {
    text-decoration: underline;
}

/* --- Checkbox e Radio (MENOS QUADRADO) --- */
QCheckBox, QRadioButton {
    spacing: 10px;
}

QCheckBox::indicator, QRadioButton::indicator {
    width: 18px;
    height: 18px;
}

QCheckBox::indicator {
    border: 1px solid #4C566A;
    border-radius: 6px; /* Mais arredondado */
    background-color: rgba(59, 66, 82, 0.7);
}

QCheckBox::indicator:checked {
    background-color: #5E81AC;
    border-color: #5E81AC;
    image: url(icons/checkmark.svg);
}

/* --- Área de Drag and Drop (COM TRANSPARÊNCIA E MENOS QUADRADO) --- */
#dropZone {
    background-color: rgba(59, 66, 82, 0.7); /* Efeito de vidro */
    border: 2px dashed rgba(76, 86, 106, 0.7);
    border-radius: 15px; /* Bem arredondado */
    padding: 20px;
}
#dropZone:hover {
    border-color: #88C0D0;
}

/* --- Barras de Progresso (COM TRANSPARÊNCIA E MENOS QUADRADO) --- */
QProgressBar {
    border: 1px solid rgba(76, 86, 106, 0.7);
    border-radius: 10px; /* Mais arredondado */
    background-color: rgba(59, 66, 82, 0.7); /* Efeito de vidro */
    text-align: center;
    color: #ECEFF4;
}

QProgressBar::chunk {
    background-color: #5E81AC;
    border-radius: 9px; /* Levemente menor que a barra */
}
"""


# --- Widget customizado para Drag and Drop ---
class DropFrame(QFrame):
    """
    Um QFrame que aceita arquivos soltos (drag-and-drop) e emite um sinal
    com os caminhos dos arquivos.
    """
    filesDropped = Signal(list)

    def __init__(self, text="Arraste e solte arquivos aqui"):
        super().__init__()
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)

        # Layout interno para centralizar o texto
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.icon_label = QLabel()
        self.icon_label.setPixmap(qta.icon('fa5s.file-upload', color='#88C0D0').pixmap(64, 64))
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.text_label = QLabel(text)
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.text_label.setStyleSheet("background-color: transparent; border: none;")

        layout.addWidget(self.icon_label)
        layout.addWidget(self.text_label)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet("#dropZone { border-color: #88C0D0; background-color: rgba(76, 86, 106, 0.8); }")
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self.setStyleSheet("#dropZone { border-color: rgba(76, 86, 106, 0.7); background-color: rgba(59, 66, 82, 0.7); }")

    def dropEvent(self, event):
        paths = [url.toLocalFile() for url in event.mimeData().urls()]
        if paths:
            self.filesDropped.emit(paths)
            self.text_label.setText(f"{len(paths)} arquivo(s) selecionado(s)")
        self.setStyleSheet("#dropZone { border-color: rgba(76, 86, 106, 0.7); background-color: rgba(59, 66, 82, 0.7); }")


# --- Janela Principal ---
class ModernApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptGuardv2 - Secure")
        self.setGeometry(100, 100, 1000, 700)
        
        # --- [NOVO] ADICIONA TRANSPARÊNCIA À JANELA ---
        # Ajuste o valor de 0.0 (invisível) a 1.0 (opaco)
        # 0.98 dá um leve toque de transparência.
        self.setWindowOpacity(0.98)
        
        # Define o ícone da janela
        self.setWindowIcon(qta.icon('fa5s.shield-alt', color='#5E81AC'))

        # Widget central e layout principal
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # --- Coluna Esquerda ---
        left_widget = self._create_left_column()
        main_layout.addWidget(left_widget, 2)  # 2/3 do espaço

        # --- Coluna Direita ---
        right_widget = self._create_right_column()
        main_layout.addWidget(right_widget, 1) # 1/3 do espaço
        
        # Aplicar o estilo QSS
        self.setStyleSheet(MODERN_QSS)

    def _create_left_column(self):
        """Cria o painel de criptografia/descriptografia."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(15)

        # 1. Área de Drag and Drop
        self.drop_zone = DropFrame("Arraste um arquivo ou pasta aqui")
        self.drop_zone.filesDropped.connect(lambda paths: print(f"Arquivos: {paths}"))
        
        # Botão de seleção de arquivo (alternativa)
        self.select_file_btn = QPushButton("Ou clique para selecionar...")
        self.select_file_btn.setObjectName("actionButton")

        drop_layout = QHBoxLayout()
        drop_layout.addWidget(self.drop_zone, 3)
        drop_layout.addWidget(self.select_file_btn, 1)
        layout.addLayout(drop_layout)

        # 2. Opções Principais (Formulário)
        form_layout = QFormLayout()
        form_layout.setSpacing(10)
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight) # Alinha labels
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["XChaCha20-Poly1305 (SecretStream)", "AES-256-GCM"])
        
        self.kdf_combo = QComboBox()
        self.kdf_combo.addItems(["Interactive", "Moderate", "Sensitive"])

        self.pad_combo = QComboBox()
        self.pad_combo.addItems(["Off", "1 KB", "10 KB", "1 MB"])

        form_layout.addRow("Algorithm:", self.algorithm_combo)
        form_layout.addRow("KDF mode:", self.kdf_combo)
        form_layout.addRow("Pad size:", self.pad_combo)
        
        # Opção de data
        self.exp_date_check = QCheckBox("Enable expiration date")
        self.exp_date_edit = QDateEdit()
        self.exp_date_edit.setCalendarPopup(True)
        self.exp_date_edit.setEnabled(False) # Desabilitado por padrão
        self.exp_date_check.toggled.connect(self.exp_date_edit.setEnabled)
        
        date_layout = QHBoxLayout()
        date_layout.addWidget(self.exp_date_check)
        date_layout.addStretch()
        date_layout.addWidget(self.exp_date_edit)
        form_layout.addRow(date_layout)
        
        layout.addLayout(form_layout)

        # 3. Senha
        (
            self.password_field_container,
            self.password_field,
            self.toggle_pass_btn,
        ) = self._create_password_field("Password...")
        layout.addWidget(self.password_field_container)
        
        # 4. Progresso
        self.progress_bar1 = QProgressBar()
        self.progress_bar1.setValue(0)
        layout.addWidget(self.progress_bar1)

        # 5. Opções Avançadas (agrupadas)
        advanced_group = QGroupBox("Opções Adicionais")
        advanced_layout = QVBoxLayout(advanced_group)
        advanced_layout.setContentsMargins(10, 10, 10, 10) # Padding para o conteúdo do grupo
        
        self.keyfile_check = QCheckBox("Use keyfile")
        self.keyfile_btn = QPushButton("Pick a keyfile...")
        self.keyfile_btn.setObjectName("actionButton")
        self.keyfile_btn.setEnabled(False)
        self.keyfile_check.toggled.connect(self.keyfile_btn.setEnabled)
        keyfile_layout = QHBoxLayout()
        keyfile_layout.addWidget(self.keyfile_check, 1)
        keyfile_layout.addWidget(self.keyfile_btn, 1)
        advanced_layout.addLayout(keyfile_layout)
        
        # Checkboxes recuados para hierarquia
        checkbox_layout = QVBoxLayout()
        checkbox_layout.setContentsMargins(20, 5, 0, 5) # Recuo esquerdo
        checkbox_layout.addWidget(QCheckBox("Hide filename (restore only extension)"))
        checkbox_layout.addWidget(QCheckBox("Secure-delete input after operation"))
        checkbox_layout.addWidget(QCheckBox("Archive folder before encrypt (ZIP)"))
        checkbox_layout.addWidget(QCheckBox("Store encrypted file in Vault"))
        checkbox_layout.addWidget(QCheckBox("Auto-extract ZIP after decrypt"))
        advanced_layout.addLayout(checkbox_layout)
        
        layout.addWidget(advanced_group)

        # 6. Botões de Ação
        action_layout = QGridLayout()
        encrypt_btn = QPushButton("Encrypt")
        encrypt_btn.setObjectName("primaryButton") # Botão principal
        encrypt_btn.setIcon(qta.icon('fa5s.lock', color='white'))
        
        decrypt_btn = QPushButton("Decrypt")
        decrypt_btn.setObjectName("actionButton")
        decrypt_btn.setIcon(qta.icon('fa5s.unlock', color='#ECEFF4'))

        verify_btn = QPushButton("Verify")
        verify_btn.setObjectName("actionButton")
        verify_btn.setIcon(qta.icon('fa5s.check', color='#ECEFF4'))
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("actionButton")
        cancel_btn.setIcon(qta.icon('fa5s.times', color='#ECEFF4'))

        action_layout.addWidget(encrypt_btn, 0, 0)
        action_layout.addWidget(decrypt_btn, 0, 1)
        action_layout.addWidget(verify_btn, 1, 0)
        action_layout.addWidget(cancel_btn, 1, 1)
        layout.addLayout(action_layout)

        # 7. Status Final
        self.progress_bar2 = QProgressBar()
        self.progress_bar2.setValue(0)
        layout.addWidget(self.progress_bar2)
        
        self.speed_label = QLabel("Speed: -- MB/s")
        self.speed_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.speed_label.setStyleSheet("background-color: transparent;")
        layout.addWidget(self.speed_label)

        # Adiciona um "espaçador" para empurrar o footer para baixo
        layout.addStretch(1)

        # 8. Footer
        footer_layout = QHBoxLayout()
        footer_layout.addWidget(QPushButton("Log", objectName="footerButton", icon=qta.icon('fa5s.file-alt', color='#88C0D0')))
        footer_layout.addWidget(QPushButton("Change Password", objectName="footerButton", icon=qta.icon('fa5s.key', color='#88C0D0')))
        footer_layout.addWidget(QPushButton("Vault", objectName="footerButton", icon=qta.icon('fa5s.database', color='#88C0D0')))
        footer_layout.addStretch(1)
        footer_layout.addWidget(QPushButton("Settings", objectName="footerButton", icon=qta.icon('fa5s.cog', color='#88C0D0')))
        layout.addLayout(footer_layout)

        return container

    def _create_right_column(self):
        """Cria o painel gerador de chaves."""
        # Usamos QScrollArea para o caso da janela ficar pequena
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background-color: transparent; border: none; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(15)

        # 1. Grupo Gerador
        gen_group = QGroupBox("KeyGuard - Generator")
        gen_layout = QVBoxLayout(gen_group)
        gen_layout.setSpacing(15)
        gen_layout.setContentsMargins(10, 10, 10, 10) # Padding para o conteúdo

        # 2. Parâmetros
        param_layout = QFormLayout()
        param_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.length_combo = QComboBox()
        self.length_combo.addItems([str(i) for i in [12, 16, 24, 32, 48, 64]])
        self.length_combo.setCurrentText("16")
        param_layout.addRow("Length:", self.length_combo)
        gen_layout.addLayout(param_layout)

        # 3. Tipos de Caracteres (Radio)
        radio_layout = QGridLayout()
        radio_layout.addWidget(QRadioButton("Numbers"), 0, 0)
        radio_layout.addWidget(QRadioButton("Letters"), 0, 1)
        radio_layout.addWidget(QRadioButton("Letters+Numbers"), 1, 0)
        radio_layout.addWidget(QRadioButton("All"), 1, 1)
        radio_layout.itemAt(2).widget().setChecked(True) # Marca "Letters+Numbers"
        gen_layout.addLayout(radio_layout)
        
        # 4. Salvar
        gen_layout.addWidget(QCheckBox("Save in vault"))

        # 5. Aplicação
        app_layout = QFormLayout()
        app_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        app_layout.addRow("Application:", QLineEdit("App / Site name"))
        gen_layout.addLayout(app_layout)

        # 6. Senha gerada
        (
            self.generated_pass_field_container,
            self.generated_pass_field,
            self.toggle_gen_pass_btn,
        ) = self._create_password_field("Generated password...")
        self.generated_pass_field.setReadOnly(True)
        gen_layout.addWidget(self.generated_pass_field_container)

        # 7. Entropia
        entropy_label = QLabel("Entropy / strength")
        entropy_label.setStyleSheet("background-color: transparent;")
        gen_layout.addWidget(entropy_label)
        # (Aqui poderia ir um QProgressBar ou similar para força)

        # 8. Botões de Geração
        gen_btn_layout = QGridLayout()
        gen_btn = QPushButton("Generate")
        gen_btn.setObjectName("secondaryButton") # Botão secundário
        gen_btn.setIcon(qta.icon('fa5s.sync-alt', color='#2E3440'))

        copy_btn = QPushButton("Copy")
        copy_btn.setObjectName("actionButton")
        copy_btn.setIcon(qta.icon('fa5s.copy', color='#ECEFF4'))

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("actionButton")
        clear_btn.setIcon(qta.icon('fa5s.trash-alt', color='#ECEFF4'))

        gen_btn_layout.addWidget(gen_btn, 0, 0)
        gen_btn_layout.addWidget(copy_btn, 0, 1)
        gen_btn_layout.addWidget(clear_btn, 0, 2)
        gen_layout.addLayout(gen_btn_layout)
        
        # 9. Botões do Vault
        vault_btn_layout = QHBoxLayout()
        copy_path_btn = QPushButton("Copy to path")
        copy_path_btn.setObjectName("actionButton")
        vault_btn = QPushButton("Vault")
        vault_btn.setObjectName("actionButton")
        
        vault_btn_layout.addWidget(copy_path_btn)
        vault_btn_layout.addWidget(vault_btn)
        gen_layout.addLayout(vault_btn_layout)
        
        layout.addWidget(gen_group)
        layout.addStretch(1) # Empurra tudo para cima

        scroll.setWidget(container)
        return scroll

    def _create_password_field(self, placeholder):
        """Helper para criar um campo de senha com botão de "mostrar"."""
        
        # O QFrame nos permite aplicar o estilo de "campo de entrada"
        # ao redor do QLineEdit e do QPushButton juntos.
        frame = QFrame()
        # [NOVO] QSS atualizado para o estilo de vidro e mais arredondado
        frame.setStyleSheet("""
            QFrame {
                background-color: rgba(59, 66, 82, 0.7);
                border: 1px solid rgba(76, 86, 106, 0.7);
                border-radius: 10px;
            }
            QFrame:focus-within {
                border: 1px solid #88C0D0;
            }
        """)
        
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(8, 0, 0, 0) # Padding esquerdo de 8, resto 0
        layout.setSpacing(0)

        line_edit = QLineEdit()
        line_edit.setPlaceholderText(placeholder)
        line_edit.setEchoMode(QLineEdit.EchoMode.Password)
        line_edit.setStyleSheet("border: none; background-color: transparent; padding: 8px 0;")
        
        toggle_btn = QPushButton()
        toggle_btn.setCheckable(True)
        toggle_btn.setIcon(qta.icon('fa5s.eye-slash', color='#88C0D0'))
        toggle_btn.setStyleSheet("background-color: transparent; border: none; padding: 8px;")
        toggle_btn.setFixedSize(QSize(36, 36)) # Tamanho fixo

        # Conectar o botão ao slot
        toggle_btn.toggled.connect(
            lambda checked: self._toggle_password_visibility(line_edit, toggle_btn, checked)
        )

        layout.addWidget(line_edit)
        layout.addWidget(toggle_btn)
        
        return frame, line_edit, toggle_btn

    def _toggle_password_visibility(self, line_edit, button, checked):
        """Alterna a visibilidade da senha no QLineEdit."""
        if checked:
            line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            button.setIcon(qta.icon('fa5s.eye', color='#88C0D0'))
        else:
            line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            button.setIcon(qta.icon('fa5s.eye-slash', color='#88C0D0'))


# --- Execução da Aplicação ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Forçar o uso do tema escuro para elementos nativos (como menus de ComboBox)
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    # ... (configurações de paleta mais detalhadas podem ser adicionadas)
    app.setPalette(palette)

    window = ModernApp()
    window.show()
    sys.exit(app.exec())