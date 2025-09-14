#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KeyGuard Vault Qt dialog.
Features: search, drag-and-drop reordering, details (Show/Hide), copy,
delete, and mass update.
"""
from __future__ import annotations

from typing import Optional
import base64
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLineEdit, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QWidget, QMessageBox,
    QAbstractItemView,
)

from .password_generator import PasswordGenerator
from .vault_backend import VaultManager


class KeyGuardVaultDialog(QDialog):
    def __init__(self, parent: Optional[QWidget], mgr: VaultManager):
        super().__init__(parent)
        self.setWindowTitle("KeyGuard Vault")
        self.setModal(True)
        self.mgr = mgr
        self.gen = PasswordGenerator()

        root = QVBoxLayout(self)
        # search
        top = QHBoxLayout(); root.addLayout(top)
        top.addWidget(QLabel("Search:"))
        self.search = QLineEdit(); self.search.setPlaceholderText("Type to filter...")
        self.search.textChanged.connect(self._refill)
        top.addWidget(self.search, 1)

        # table
        self.table = QTableWidget(0, 2, self)
        self.table.setHorizontalHeaderLabels(["Application", "Password"])
        # --- FIX: enums corretas do QAbstractItemView (compat Qt6/PySide6)
        SB = getattr(QAbstractItemView, "SelectionBehavior", QAbstractItemView)
        SM = getattr(QAbstractItemView, "SelectionMode", QAbstractItemView)
        DM = getattr(QAbstractItemView, "DragDropMode", QAbstractItemView)
        self.table.setSelectionBehavior(SB.SelectRows)
        self.table.setSelectionMode(SM.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setDragDropMode(DM.InternalMove)
        # melhora DnD visual/UX
        self.table.setDragEnabled(True)
        self.table.setAcceptDrops(True)
        self.table.setDropIndicatorShown(True)
        root.addWidget(self.table, 1)

        # buttons
        bar = QHBoxLayout(); root.addLayout(bar)
        self.btn_details = QPushButton("Details")
        self.btn_copy = QPushButton("Copy")
        self.btn_delete = QPushButton("Delete")
        self.btn_update_all = QPushButton("Update all")
        self.btn_close = QPushButton("Close")
        for b in (self.btn_details, self.btn_copy, self.btn_delete, self.btn_update_all, self.btn_close):
            bar.addWidget(b)
        bar.addStretch()
        self.btn_close.clicked.connect(self.accept)
        self.btn_details.clicked.connect(self._details)
        self.btn_copy.clicked.connect(self._copy_sel)
        self.btn_delete.clicked.connect(self._delete_sel)
        self.btn_update_all.clicked.connect(self._update_all)

        self.table.model().rowsMoved.connect(self._persist_order)

        self._refill()

    # ---- fill / filter -------------------------------------------------
    def _entry_password(self, entry) -> str:
        try:
            b = base64.b64decode(entry.password_b64)
            return b.decode("utf-8", errors="replace")
        except Exception:
            return ""
    def _refill(self) -> None:
        query = (self.search.text() or "").lower()
        items = []
        for name in self.mgr.list_entries():
            if query in name.lower():
                items.append(name)
        self.table.setRowCount(0)
        for name in items:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(name))
            self.table.setItem(r, 1, QTableWidgetItem("********"))

    # ---- actions -------------------------------------------------------
    def _selected_name(self) -> Optional[str]:
        r = self.table.currentRow()
        if r < 0:
            return None
        return self.table.item(r, 0).text()

    def _details(self) -> None:
        name = self._selected_name()
        if not name:
            return
        entry = self.mgr.entries.get(name)
        if not entry:
            return
        pwd = self._entry_password(entry)

        d = QDialog(self); d.setWindowTitle(name)
        lay = QVBoxLayout(d)
        lay.addWidget(QLabel(f"Application: {name}"))
        pwd_row = QHBoxLayout(); lay.addLayout(pwd_row)
        le = QLineEdit("*" * min(16, len(pwd))); le.setReadOnly(True)
        btn = QPushButton("Show")
        def toggle():
            if btn.text() == "Show":
                le.setText(pwd); btn.setText("Hide")
            else:
                le.setText("*" * min(16, len(pwd))); btn.setText("Show")
        btn.clicked.connect(toggle)
        pwd_row.addWidget(le, 1); pwd_row.addWidget(btn)

        def copy_and_close():
            QGuiApplication.clipboard().setText(pwd)
            QTimer.singleShot(15000, lambda: QGuiApplication.clipboard().clear())
            d.accept()
        copy = QPushButton("Copy"); copy.clicked.connect(copy_and_close)
        lay.addWidget(copy)
        d.exec()

    def _copy_sel(self) -> None:
        name = self._selected_name()
        if not name:
            return
        e = self.mgr.entries.get(name)
        if not e:
            return
        s = self._entry_password(e)
        QGuiApplication.clipboard().setText(s)
        QTimer.singleShot(15000, lambda: QGuiApplication.clipboard().clear())

    def _delete_sel(self) -> None:
        name = self._selected_name()
        if not name:
            return
        if QMessageBox.question(self, "Confirm", f"Remove '{name}' from vault?") != QMessageBox.Yes:
            return
        try:
            self.mgr.delete_entry(name)
            self._refill()
        except Exception as ex:
            QMessageBox.critical(self, "Error", str(ex))

    def _persist_order(self, *_args) -> None:
        new_order = []
        for r in range(self.table.rowCount()):
            new_order.append(self.table.item(r, 0).text())
        self.mgr.reorder(new_order)

    def _update_all(self) -> None:
        if not self.mgr.entries:
            QMessageBox.information(self, "Info", "Vault is empty.")
            return
        ok1 = QMessageBox.question(
            self,
            "Confirm",
            "New passwords will be generated for all entries.\nThis cannot be undone.\nContinue?",
        ) == QMessageBox.Yes
        if not ok1:
            return
        try:
            total = self.mgr.update_all_passwords(self.gen, length=20, charset_key="full")
            QMessageBox.information(self, "Done", f"{total} passwords updated.")
        except Exception as ex:
            QMessageBox.critical(self, "Error", f"Failed to update: {ex}")
        self._refill()
