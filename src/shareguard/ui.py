from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from PySide6.QtCore import (
    QElapsedTimer,
    QObject,
    QPointF,
    QRectF,
    QRunnable,
    Qt,
    QThreadPool,
    QTimer,
    QUrl,
    Signal,
    Slot,
)
from PySide6.QtGui import QColor, QDesktopServices, QPainter, QPen, QPolygonF, QIcon, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QScrollArea,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import __version__
from .models import RecommendedAction, ScanResult, Severity
from .packager import SafePackager
from .reporting import write_scan_report_bundle
from .scanner import FolderScanner


MINIMUM_SCAN_FEEDBACK_MS = 1600
MANDATORY_EXCLUSION_CATEGORY = "gereksiz-dizin"


class WorkerSignals(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str, int)


class ScanWorker(QRunnable):
    def __init__(self, folder: Path) -> None:
        super().__init__()
        self.folder = folder
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        last_emitted = 0.0

        def report(path: str, count: int) -> None:
            nonlocal last_emitted
            now = time.monotonic()
            if count == 1 or now - last_emitted >= 0.075:
                self.signals.progress.emit(path, count)
                last_emitted = now

        try:
            result = FolderScanner().scan(self.folder, report)
        except Exception as exc:
            self.signals.failed.emit(str(exc))
            return
        self.signals.finished.emit(result)


class PackageWorker(QRunnable):
    def __init__(self, result: ScanResult, output_parent: Path, excluded: list[str]) -> None:
        super().__init__()
        self.result = result
        self.output_parent = output_parent
        self.excluded = excluded
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            package = SafePackager().build(self.result, self.output_parent, self.excluded)
        except Exception as exc:
            self.signals.failed.emit(str(exc))
            return
        self.signals.finished.emit(package)


class ReportWorker(QRunnable):
    def __init__(self, result: ScanResult, output_parent: Path) -> None:
        super().__init__()
        self.result = result
        self.output_parent = output_parent
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            paths = write_scan_report_bundle(self.output_parent, self.result)
        except Exception as exc:
            self.signals.failed.emit(str(exc))
            return
        self.signals.finished.emit(paths)


class ShieldMark(QWidget):
    """Code-drawn brand mark so the executable needs no external icon asset."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(44, 48)

    def paintEvent(self, event: object) -> None:  # noqa: ARG002
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        shield = QPolygonF(
            [
                QPointF(22, 2),
                QPointF(40, 9),
                QPointF(37, 30),
                QPointF(22, 45),
                QPointF(7, 30),
                QPointF(4, 9),
            ]
        )
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#3b82f6"))
        painter.drawPolygon(shield)
        painter.setPen(QPen(QColor("white"), 4, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawLine(QPointF(13, 24), QPointF(19, 30))
        painter.drawLine(QPointF(19, 30), QPointF(32, 17))


class ActivitySpinner(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(52, 52)
        self._angle = 0
        self._state = "idle"
        self._timer = QTimer(self)
        self._timer.setInterval(35)
        self._timer.timeout.connect(self._advance)

    def start(self) -> None:
        self._state = "busy"
        self._timer.start()
        self.update()

    def stop(self) -> None:
        self._timer.stop()
        self._angle = 0
        self._state = "done"
        self.update()

    def fail(self) -> None:
        self._timer.stop()
        self._angle = 0
        self._state = "error"
        self.update()

    def reset(self) -> None:
        self._timer.stop()
        self._angle = 0
        self._state = "idle"
        self.update()

    def _advance(self) -> None:
        self._angle = (self._angle + 8) % 360
        self.update()

    def paintEvent(self, event: object) -> None:  # noqa: ARG002
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        ring = QRectF(8, 8, 36, 36)
        if self._state in {"done", "error"}:
            color = QColor("#087f5b" if self._state == "done" else "#b42318")
            painter.setPen(Qt.NoPen)
            painter.setBrush(color)
            painter.drawEllipse(ring)
            painter.setPen(QPen(QColor("white"), 4, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            if self._state == "done":
                painter.drawLine(QPointF(17, 26), QPointF(23, 32))
                painter.drawLine(QPointF(23, 32), QPointF(35, 19))
            else:
                painter.drawLine(QPointF(19, 19), QPointF(33, 33))
                painter.drawLine(QPointF(33, 19), QPointF(19, 33))
            return
        if self._state == "idle":
            painter.setPen(QPen(QColor("#b8c5d6"), 5))
            painter.drawEllipse(ring)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor("#7c8da5"))
            painter.drawEllipse(QRectF(23, 23, 6, 6))
            return
        painter.setPen(QPen(QColor("#dbeafe"), 6, Qt.SolidLine, Qt.RoundCap))
        painter.drawEllipse(ring)
        painter.setPen(QPen(QColor("#2563eb"), 6, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(ring, int(-self._angle * 16), 105 * 16)


class MetricCard(QFrame):
    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("metricCard")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(72)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(2)
        self.value_label = QLabel("—")
        self.value_label.setObjectName("metricValue")
        self.title_label = QLabel(title)
        self.title_label.setObjectName("metricTitle")
        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)

    def set_value(self, value: str, color: str = "#10213b") -> None:
        self.value_label.setText(value)
        self.value_label.setStyleSheet(f"color: {color};")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"ShareGuard {__version__} — Paylaşım Öncesi Denetim")
        icon = QPixmap(48, 48)
        icon.fill(QColor("#303c38"))
        painter = QPainter(icon)
        painter.setPen(QColor("white"))
        font = painter.font()
        font.setPixelSize(32)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(icon.rect(), Qt.AlignCenter, "S")
        painter.end()
        self.setWindowIcon(QIcon(icon))
        self.resize(1280, 820)
        self.setMinimumSize(920, 640)
        self.setAcceptDrops(True)

        self.thread_pool = QThreadPool.globalInstance()
        self.scan_result: ScanResult | None = None
        self._scan_clock = QElapsedTimer()
        self._scan_elapsed_ms = 0
        self._populating_table = False
        self._latest_html_report: Path | None = None

        self._build_ui()
        self._connect_signals()
        self._reset_result_view()

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("appRoot")
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        hero = QFrame()
        hero.setObjectName("hero")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(28, 12, 28, 12)
        hero_layout.setSpacing(14)
        title_box = QVBoxLayout()
        title_box.setSpacing(1)
        title = QLabel("ShareGuard")
        title.setObjectName("heroTitle")
        subtitle = QLabel("Dosya paylaşım denetimi")
        subtitle.setObjectName("heroSubtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        hero_layout.addLayout(title_box)
        hero_layout.addStretch(1)
        privacy = QLabel(f"Yerel tarama  ·  {__version__}")
        privacy.setObjectName("privacyBadge")
        hero_layout.addWidget(privacy)
        root_layout.addWidget(hero)

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(28, 12, 28, 14)
        body_layout.setSpacing(9)

        source_card = QFrame()
        source_card.setObjectName("card")
        source_layout = QVBoxLayout(source_card)
        source_layout.setContentsMargins(18, 10, 18, 10)
        source_layout.setSpacing(6)
        source_title = QLabel("Klasör")
        source_title.setObjectName("sectionTitle")
        source_layout.addWidget(source_title)
        source_row = QHBoxLayout()
        source_row.setSpacing(9)
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Klasör seçin veya buraya sürükleyin")
        self.path_input.setClearButtonEnabled(True)
        self.path_input.setAccessibleName("Taranacak klasör yolu")
        self.choose_button = QPushButton("Klasör Seç")
        self.choose_button.setProperty("secondary", True)
        self.scan_button = QPushButton("Tara")
        self.scan_button.setObjectName("primaryButton")
        source_row.addWidget(self.path_input, 1)
        source_row.addWidget(self.choose_button)
        source_row.addWidget(self.scan_button)
        source_layout.addLayout(source_row)
        body_layout.addWidget(source_card)

        self.activity_card = QFrame()
        self.activity_card.setObjectName("activityCard")
        activity_layout = QHBoxLayout(self.activity_card)
        activity_layout.setContentsMargins(18, 8, 18, 8)
        activity_layout.setSpacing(15)
        self.spinner = ActivitySpinner()
        activity_layout.addWidget(self.spinner)
        activity_text = QVBoxLayout()
        activity_text.setSpacing(3)
        self.activity_title = QLabel("Taranıyor…")
        self.activity_title.setObjectName("activityTitle")
        self.activity_detail = QLabel("")
        self.activity_detail.setObjectName("activityDetail")
        self.activity_detail.setWordWrap(True)
        activity_text.addWidget(self.activity_title)
        activity_text.addWidget(self.activity_detail)
        activity_layout.addLayout(activity_text, 1)
        self.progress = QProgressBar()
        self.progress.setFixedWidth(220)
        self.progress.setTextVisible(False)
        activity_layout.addWidget(self.progress)
        body_layout.addWidget(self.activity_card)
        self.activity_card.hide()

        metrics = QGridLayout()
        metrics.setHorizontalSpacing(10)
        self.verdict_card = MetricCard("Paylaşım durumu")
        self.blocker_card = MetricCard("Engel")
        self.review_card = MetricCard("İnceleme / hata")
        self.files_card = MetricCard("Taranan dosya")
        metrics.addWidget(self.verdict_card, 0, 0)
        metrics.addWidget(self.blocker_card, 0, 1)
        metrics.addWidget(self.review_card, 0, 2)
        metrics.addWidget(self.files_card, 0, 3)
        body_layout.addLayout(metrics)

        findings_card = QFrame()
        findings_card.setObjectName("card")
        findings_layout = QVBoxLayout(findings_card)
        findings_layout.setContentsMargins(18, 10, 18, 10)
        findings_layout.setSpacing(7)
        findings_head = QHBoxLayout()
        findings_title = QLabel("Bulgular")
        findings_title.setObjectName("sectionTitle")
        self.finding_count_label = QLabel("0 kayıt")
        self.finding_count_label.setObjectName("counterBadge")
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("Tüm seviyeler", "all")
        self.filter_combo.addItem("Engeller", Severity.BLOCKER.value)
        self.filter_combo.addItem("İncelenecek", Severity.REVIEW.value)
        self.filter_combo.addItem("Bilgi", Severity.INFO.value)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Dosya veya bulgu ara…")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setFixedWidth(240)
        findings_head.addWidget(findings_title)
        findings_head.addWidget(self.finding_count_label)
        findings_head.addStretch(1)
        findings_head.addWidget(self.filter_combo)
        findings_head.addWidget(self.search_input)
        findings_layout.addLayout(findings_head)

        self.table = QTableWidget(0, 7)
        self.table.setObjectName("findingsTable")
        self.table.setHorizontalHeaderLabels(
            ["Çıkar", "Seviye", "Kimlik", "Dosya", "Satır", "Bulgu", "Kanıt (yalnız yerel)"]
        )
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.ElideMiddle)
        self.table.setMinimumHeight(150)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(36)
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setStretchLastSection(False)
        for column in (0, 1, 2, 4):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        # Evidence may contain a long token. Keep it readable and resizable
        # without allowing its full length to expand the whole window.
        header.setSectionResizeMode(6, QHeaderView.Interactive)
        self.table.setColumnWidth(6, 220)
        self.table.setColumnHidden(2, True)
        self.table.setColumnHidden(4, True)
        findings_layout.addWidget(self.table, 1)

        self.details_label = QLabel("Ayrıntılar için bir bulgu seçin.")
        self.details_label.setObjectName("detailsPanel")
        self.details_label.setTextFormat(Qt.PlainText)
        self.details_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.details_label.setWordWrap(True)
        self.details_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        details_scroll = QScrollArea()
        details_scroll.setObjectName("detailsScroll")
        details_scroll.setWidgetResizable(True)
        details_scroll.setWidget(self.details_label)
        details_scroll.setFixedHeight(94)
        findings_layout.addWidget(details_scroll)
        body_layout.addWidget(findings_card, 1)

        footer = QHBoxLayout()
        footer.setSpacing(10)
        self.status_label = QLabel("Hazır")
        self.status_label.setObjectName("statusText")
        self.open_source_button = QPushButton("Kaynak Klasörü Aç")
        self.open_source_button.setProperty("secondary", True)
        self.open_source_button.setEnabled(False)
        self.save_report_button = QPushButton("Raporu Kaydet")
        self.save_report_button.setProperty("secondary", True)
        self.save_report_button.setEnabled(False)
        self.open_report_button = QPushButton("Raporu Aç")
        self.open_report_button.setProperty("secondary", True)
        self.open_report_button.setEnabled(False)
        self.package_button = QPushButton("Temiz Paketi Oluştur")
        self.package_button.setObjectName("successButton")
        self.package_button.setEnabled(False)
        footer.addWidget(self.status_label, 1)
        self.open_source_button.hide()
        footer.addWidget(self.save_report_button)
        footer.addWidget(self.open_report_button)
        footer.addWidget(self.package_button)
        body_layout.addLayout(footer)

        root_layout.addWidget(body, 1)
        self.setCentralWidget(root)
        self.setStyleSheet(self._stylesheet())

    def _connect_signals(self) -> None:
        self.choose_button.clicked.connect(self.choose_folder)
        self.scan_button.clicked.connect(self.start_scan)
        self.package_button.clicked.connect(self.start_package)
        self.open_source_button.clicked.connect(self.open_source_folder)
        self.save_report_button.clicked.connect(self.start_report)
        self.open_report_button.clicked.connect(self.open_latest_report)
        self.path_input.textChanged.connect(self._source_path_changed)
        self.path_input.returnPressed.connect(self.start_scan)
        self.filter_combo.currentIndexChanged.connect(self._apply_filter)
        self.search_input.textChanged.connect(self._apply_filter)
        self.table.itemSelectionChanged.connect(self._show_selected_finding)
        self.table.itemChanged.connect(self._table_item_changed)

    @staticmethod
    def _stylesheet() -> str:
        return """
            QMainWindow, QWidget#appRoot { background: #f4f7fb; }
            QWidget { font-family: 'Segoe UI'; font-size: 10pt; color: #15243b; }
            QFrame#hero { background: #0f1f38; border: 0; }
            QLabel#heroTitle { color: white; font-size: 20pt; font-weight: 700; }
            QLabel#heroSubtitle { color: #afc1dc; }
            QLabel#privacyBadge { color: #bfe0ff; background: #193452; border: 1px solid #315477;
                                  border-radius: 13px; padding: 7px 12px; font-size: 8.5pt; font-weight: 600; }
            QLabel#stepChip { color: #53647b; background: #e8eef7; border-radius: 13px;
                              padding: 6px 12px; font-size: 9pt; font-weight: 600; }
            QFrame#card, QFrame#metricCard { background: white; border: 1px solid #dfe7f2; border-radius: 11px; }
            QFrame#activityCard { background: #f0f7ff; border: 1px solid #bfdbfe; border-radius: 11px; }
            QLabel#sectionTitle { color: #10213b; font-size: 12pt; font-weight: 700; }
            QLabel#hint, QLabel#activityDetail { color: #66758b; font-size: 9pt; }
            QLabel#activityTitle { color: #17345c; font-size: 10.5pt; font-weight: 700; }
            QLabel#metricValue { font-size: 18pt; font-weight: 750; }
            QLabel#metricTitle { color: #6b7890; font-size: 9pt; }
            QLabel#counterBadge { color: #36506f; background: #edf2f8; border-radius: 10px; padding: 4px 9px; }
            QLabel#detailsPanel { color: #52627a; background: #f7f9fc; border: 1px solid #e5ebf3;
                                  border-radius: 7px; padding: 9px 11px; }
            QLabel#statusText { color: #5c6d83; }
            QLineEdit, QComboBox { background: white; border: 1px solid #cfd9e7; border-radius: 7px;
                                  padding: 8px 10px; selection-background-color: #2563eb; }
            QLineEdit:focus, QComboBox:focus { border-color: #3b82f6; }
            QLineEdit:disabled { background: #eef2f7; color: #8491a4; }
            QPushButton { background: #2563eb; color: white; border: 0; border-radius: 7px;
                          padding: 9px 15px; font-weight: 650; }
            QPushButton:hover:!disabled { background: #1d4ed8; }
            QPushButton:disabled { background: #b8c3d1; color: #eef2f7; }
            QPushButton[secondary="true"] { background: white; color: #29415f; border: 1px solid #cfd9e7; }
            QPushButton[secondary="true"]:hover:!disabled { background: #f0f5fb; border-color: #9db0c8; }
            QPushButton#successButton { background: #087f5b; padding-left: 18px; padding-right: 18px; }
            QPushButton#successButton:hover:!disabled { background: #06694b; }
            QProgressBar { background: #dbeafe; border: 0; border-radius: 5px; height: 9px; }
            QProgressBar::chunk { background: #2563eb; border-radius: 5px; }
            QTableWidget#findingsTable { background: white; alternate-background-color: #f8fafc;
                                         border: 1px solid #e2e8f0; border-radius: 7px;
                                         selection-background-color: #dbeafe; selection-color: #10213b; }
            QHeaderView::section { background: #edf2f8; color: #41536b; border: 0;
                                   border-bottom: 1px solid #dbe3ee; padding: 8px; font-weight: 650; }
            QScrollBar:vertical { background: #f1f5f9; width: 11px; }
            QScrollBar::handle:vertical { background: #b8c5d6; border-radius: 5px; min-height: 28px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
            QMainWindow, QWidget#appRoot { background: #f5f5f4; }
            QWidget { color: #26282c; }
            QFrame#hero { background: white; border-bottom: 1px solid #dededb; }
            QLabel#heroTitle { color: #202225; font-size: 18pt; }
            QLabel#heroSubtitle, QLabel#privacyBadge { color: #676b70; background: transparent;
                border: none; padding: 0; font-size: 9pt; font-weight: 400; }
            QFrame#card, QFrame#metricCard { border: 1px solid #dededb; border-radius: 6px; }
            QFrame#activityCard { background: #fafaf9; border: 1px solid #dededb; border-radius: 6px; }
            QLabel#sectionTitle, QLabel#activityTitle { color: #26282c; }
            QLabel#metricValue { font-size: 16pt; font-weight: 600; }
            QLabel#metricTitle, QLabel#activityDetail, QLabel#statusText { color: #676b70; }
            QLabel#counterBadge { color: #676b70; background: transparent; padding: 0 6px; }
            QScrollArea#detailsScroll { border: 0; border-top: 1px solid #e6e6e3; background: white; }
            QLabel#detailsPanel { color: #50545a; background: white; border: none; border-radius: 0; padding: 10px 2px; }
            QLineEdit, QComboBox { border: 1px solid #cfcfca; border-radius: 4px; padding: 7px 9px;
                selection-background-color: #dcebe5; selection-color: #202225; }
            QLineEdit:focus, QComboBox:focus { border-color: #477364; }
            QPushButton { background: #303c38; border-radius: 4px; padding: 9px 16px; font-weight: 600; }
            QPushButton:hover:!disabled { background: #1d2925; }
            QPushButton[secondary="true"] { background: white; color: #30343b; border: 1px solid #cfcfca; }
            QPushButton[secondary="true"]:hover:!disabled { background: #f0f1ef; border-color: #989d97; }
            QPushButton#successButton { background: #303c38; }
            QPushButton#successButton:hover:!disabled { background: #1d2925; }
            QPushButton#primaryButton, QPushButton#successButton { color: white; }
            QPushButton:disabled, QPushButton#successButton:disabled,
            QPushButton[secondary="true"]:disabled { background: #eeeeeb; color: #91958f; border: 1px solid #e0e0dc; }
            QProgressBar { background: #e4e7e3; height: 4px; border-radius: 2px; }
            QProgressBar::chunk { background: #477364; border-radius: 2px; }
            QTableWidget#findingsTable { background: white; alternate-background-color: #fafaf9;
                border: 0; border-radius: 0; selection-background-color: #e5ede8; selection-color: #202225; }
            QHeaderView::section { background: #f5f5f3; color: #555b58; border-bottom: 1px solid #dededb; padding: 8px 4px; }
            QScrollBar:vertical { background: #f5f5f3; }
            QScrollBar::handle:vertical { background: #c2c5bf; }
        """

    @Slot()
    def choose_folder(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Taranacak klasörü seç")
        if selected:
            self.path_input.setText(selected)

    def dragEnterEvent(self, event: object) -> None:
        mime_data = event.mimeData()  # type: ignore[attr-defined]
        urls = mime_data.urls() if mime_data.hasUrls() else []
        if len(urls) == 1 and urls[0].isLocalFile() and Path(urls[0].toLocalFile()).is_dir():
            event.acceptProposedAction()  # type: ignore[attr-defined]

    def dropEvent(self, event: object) -> None:
        urls = event.mimeData().urls()  # type: ignore[attr-defined]
        if urls:
            dropped = Path(urls[0].toLocalFile())
            if dropped.is_dir():
                self.path_input.setText(str(dropped))
                event.acceptProposedAction()  # type: ignore[attr-defined]

    @Slot(str)
    def _source_path_changed(self, text: str) -> None:
        self.open_source_button.setEnabled(Path(text.strip()).is_dir())
        if self.scan_result is None:
            return
        try:
            entered = Path(text.strip()).expanduser().resolve()
        except OSError:
            entered = Path(text.strip())
        if entered != self.scan_result.root:
            self.scan_result = None
            self._latest_html_report = None
            self.table.setRowCount(0)
            self.package_button.setEnabled(False)
            self.save_report_button.setEnabled(False)
            self.open_report_button.setEnabled(False)
            self._reset_result_view()
            self.activity_title.setText("Klasör değişti — yeniden tarama gerekli")
            self.activity_detail.setText("Temiz paket oluşturabilmek için yeni klasörü tarayın.")
            self.status_label.setText("Kaynak klasör değiştirildi.")

    def _set_busy(self, busy: bool, title: str, detail: str) -> None:
        self.path_input.setEnabled(not busy)
        self.choose_button.setEnabled(not busy)
        self.scan_button.setEnabled(not busy)
        self.filter_combo.setEnabled(not busy)
        self.search_input.setEnabled(not busy)
        self.open_source_button.setEnabled(not busy and Path(self.path_input.text().strip()).is_dir())
        self.save_report_button.setEnabled(not busy and self.scan_result is not None)
        self.open_report_button.setEnabled(
            not busy and self._latest_html_report is not None and self._latest_html_report.is_file()
        )
        self.activity_title.setText(title)
        self.activity_detail.setText(detail)
        self.activity_card.setVisible(busy)
        self.progress.setVisible(busy)
        if busy:
            self.package_button.setEnabled(False)
            self.spinner.start()
            self.progress.setRange(0, 0)
        else:
            self.spinner.stop()
            self.progress.setRange(0, 1)
            self.progress.setValue(1)
            self._update_package_availability()

    @Slot()
    def start_scan(self) -> None:
        folder = Path(self.path_input.text().strip()).expanduser()
        if not folder.is_dir():
            QMessageBox.warning(self, "Geçersiz klasör", "Lütfen var olan bir klasör seçin.")
            return
        folder = folder.resolve()
        self.scan_result = None
        self._latest_html_report = None
        self.table.setRowCount(0)
        self._reset_result_view()
        self._scan_clock.start()
        self._set_busy(
            True,
            "Klasör güvenlik açısından taranıyor…",
            "Dosya yapısı hazırlanıyor; secret, kişisel veri, metadata ve gereksiz çıktılar aranıyor.",
        )
        self.status_label.setText("Tarama başladı…")
        worker = ScanWorker(folder)
        worker.signals.progress.connect(self._scan_progress)
        worker.signals.finished.connect(self._scan_worker_finished)
        worker.signals.failed.connect(self.operation_failed)
        self.thread_pool.start(worker)

    @Slot(str, int)
    def _scan_progress(self, path: str, count: int) -> None:
        shortened = path if len(path) <= 100 else "…" + path[-99:]
        self.activity_title.setText(f"{count} dosya incelendi")
        self.activity_detail.setText(shortened)
        self.status_label.setText("Gerçek dosya taraması devam ediyor…")

    @Slot(object)
    def _scan_worker_finished(self, result: ScanResult) -> None:
        elapsed = self._scan_clock.elapsed()
        self._scan_elapsed_ms = max(elapsed, MINIMUM_SCAN_FEEDBACK_MS)
        remaining = max(0, MINIMUM_SCAN_FEEDBACK_MS - elapsed)
        if remaining:
            self.activity_title.setText("Tarama tamamlandı, sonuç görünümü hazırlanıyor…")
            self.activity_detail.setText(
                f"{result.stats.files_seen} dosyanın bulguları sınıflandırılıyor ve özet kartları hazırlanıyor."
            )
            self.status_label.setText("Sonuçlar hazırlanıyor…")
            QTimer.singleShot(remaining, lambda: self.scan_finished(result))
            return
        self.scan_finished(result)

    @Slot(object)
    def scan_finished(self, result: ScanResult) -> None:
        self.scan_result = result
        findings = result.sorted_findings()
        self._populating_table = True
        self.table.setRowCount(len(findings))
        severity_colors = {
            Severity.BLOCKER: QColor("#b42318"),
            Severity.REVIEW: QColor("#a15c00"),
            Severity.INFO: QColor("#1d4ed8"),
        }
        labels = {Severity.BLOCKER: "ENGEL", Severity.REVIEW: "İNCELE", Severity.INFO: "BİLGİ"}
        for row, finding in enumerate(findings):
            checkbox = QTableWidgetItem()
            mandatory = finding.category == MANDATORY_EXCLUSION_CATEGORY
            flags = Qt.ItemIsEnabled | Qt.ItemIsSelectable
            if not mandatory:
                flags |= Qt.ItemIsUserCheckable
            checkbox.setFlags(flags)
            should_exclude = mandatory or finding.recommended_action is RecommendedAction.EXCLUDE
            checkbox.setCheckState(Qt.Checked if should_exclude else Qt.Unchecked)
            checkbox.setData(Qt.UserRole, mandatory)
            checkbox.setToolTip(
                "Tarama sırasında içeriği atlanan bu dizin güvenlik için zorunlu olarak çıkarılır."
                if mandatory
                else "İşaretliyse bu dosya temiz pakete dahil edilmez."
            )
            self.table.setItem(row, 0, checkbox)
            values = [
                labels[finding.severity],
                finding.finding_id,
                finding.relative_path,
                str(finding.line_number or ""),
                finding.title,
                finding.local_evidence or "—",
            ]
            for column, value in enumerate(values, start=1):
                item = QTableWidgetItem(value)
                item.setToolTip(finding.explanation)
                if column == 1:
                    item.setForeground(severity_colors[finding.severity])
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                    item.setData(Qt.UserRole, finding.severity.value)
                self.table.setItem(row, column, item)
        self._populating_table = False

        verdicts = {
            "BLOCKED": ("HAZIR DEĞİL", "#b42318"),
            "REVIEW": ("KONTROL ET", "#a15c00"),
            "READY": ("HAZIR", "#087f5b"),
        }
        verdict_label, verdict_color = verdicts[result.verdict]
        self.verdict_card.set_value(verdict_label, verdict_color)
        self.blocker_card.set_value(str(len(result.blockers)), "#b42318" if result.blockers else "#087f5b")
        review_total = len(result.reviews) + len(result.errors)
        self.review_card.set_value(str(review_total), "#a15c00" if review_total else "#087f5b")
        self.files_card.set_value(str(result.stats.files_seen), "#30343b")
        self._apply_filter()
        seconds = self._scan_elapsed_ms / 1000
        error_note = f" {len(result.errors)} öğe okunamadı/atlandı." if result.errors else ""
        self._set_busy(
            False,
            f"Tarama tamamlandı — {verdict_label}",
            f"{result.stats.files_seen} dosya ve {result.stats.directories_seen} dizin incelendi. "
            f"{len(findings)} bulgu sınıflandırıldı.{error_note}",
        )
        self.status_label.setText(f"Tamamlandı · {seconds:.1f} sn")
        if findings:
            self.table.selectRow(0)
        elif result.errors:
            self.details_label.setText("Tarama hataları:\n" + "\n".join(result.errors[:5]))
        else:
            self.details_label.setText("Bulgu bulunmadı.")

    def _reset_result_view(self) -> None:
        self.spinner.reset()
        self.verdict_card.set_value("—")
        self.blocker_card.set_value("0")
        self.review_card.set_value("0")
        self.files_card.set_value("0")
        self.finding_count_label.setText("0 kayıt")
        self.details_label.setText("Ayrıntılar için bir bulgu seçin.")
        self.activity_card.hide()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.save_report_button.setEnabled(False)
        self.open_report_button.setEnabled(False)

    @Slot()
    def _apply_filter(self) -> None:
        wanted = self.filter_combo.currentData() or "all"
        query = self.search_input.text().strip().casefold()
        visible = 0
        for row in range(self.table.rowCount()):
            severity_item = self.table.item(row, 1)
            severity = severity_item.data(Qt.UserRole) if severity_item else ""
            haystack = " ".join(
                self.table.item(row, column).text()
                for column in range(1, self.table.columnCount())
                if self.table.item(row, column)
            ).casefold()
            show = (wanted == "all" or severity == wanted) and (not query or query in haystack)
            self.table.setRowHidden(row, not show)
            visible += int(show)
        total = self.table.rowCount()
        self.finding_count_label.setText(f"{visible}/{total} kayıt" if visible != total else f"{total} kayıt")

    @Slot(QTableWidgetItem)
    def _table_item_changed(self, item: QTableWidgetItem) -> None:
        if self._populating_table or item.column() != 0:
            return
        path_item = self.table.item(item.row(), 3)
        if not path_item:
            return
        path = path_item.text()
        self._populating_table = True
        for row in range(self.table.rowCount()):
            sibling_path = self.table.item(row, 3)
            sibling_checkbox = self.table.item(row, 0)
            if sibling_path and sibling_checkbox and sibling_path.text() == path:
                if sibling_checkbox.data(Qt.UserRole):
                    sibling_checkbox.setCheckState(Qt.Checked)
                else:
                    sibling_checkbox.setCheckState(item.checkState())
        self._populating_table = False
        self._update_package_availability()

    def _update_package_availability(self) -> None:
        if self.scan_result is None:
            self.package_button.setEnabled(False)
            return
        unresolved = 0
        for row in range(self.table.rowCount()):
            severity = self.table.item(row, 1)
            checkbox = self.table.item(row, 0)
            if severity and checkbox and severity.data(Qt.UserRole) == Severity.BLOCKER.value:
                unresolved += int(checkbox.checkState() != Qt.Checked)
        self.package_button.setEnabled(unresolved == 0)
        if unresolved:
            self.status_label.setText(f"{unresolved} engelleyici bulgu çıkarılmadan temiz paket oluşturulamaz.")

    @Slot()
    def _show_selected_finding(self) -> None:
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        finding_id = self.table.item(row, 2).text()
        location = self.table.item(row, 3).text()
        title_item = self.table.item(row, 5)
        evidence = self.table.item(row, 6).text()
        explanation = title_item.toolTip()
        self.details_label.setText(
            f"{finding_id} • {location}\n{title_item.text()} — {explanation}\n"
            f"Kanıt (raporda maskelenir): {evidence}"
        )

    def _checked_exclusions(self) -> list[str]:
        paths: list[str] = []
        for row in range(self.table.rowCount()):
            checkbox = self.table.item(row, 0)
            path = self.table.item(row, 3)
            if checkbox and path and checkbox.checkState() == Qt.Checked:
                paths.append(path.text())
        return paths

    @Slot()
    def open_source_folder(self) -> None:
        folder = Path(self.path_input.text().strip())
        if folder.is_dir():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder.resolve())))

    @Slot()
    def start_report(self) -> None:
        if not self.scan_result:
            return
        output_parent = QFileDialog.getExistingDirectory(self, "Denetim raporunun kaydedileceği klasörü seç")
        if not output_parent:
            return
        self._set_busy(
            True,
            "Denetim raporu hazırlanıyor…",
            "Tarama özeti ve maskeli bulgular HTML ve JSON biçiminde kaydediliyor.",
        )
        self.status_label.setText("Kaynak dosyalar değiştirilmeden rapor hazırlanıyor…")
        worker = ReportWorker(self.scan_result, Path(output_parent))
        worker.signals.finished.connect(self.report_finished)
        worker.signals.failed.connect(self.operation_failed)
        self.thread_pool.start(worker)

    @Slot(object)
    def report_finished(self, paths: object) -> None:
        html_path, json_path = paths  # type: ignore[misc]
        self._latest_html_report = Path(html_path)
        self._set_busy(
            False,
            "Denetim raporu kaydedildi",
            "İnsan tarafından okunabilir HTML ve makine tarafından okunabilir JSON raporu hazır.",
        )
        self.status_label.setText(f"Raporlar kaydedildi • {Path(html_path).parent}")
        answer = QMessageBox.information(
            self,
            "Rapor hazır",
            f"HTML raporu:\n{html_path}\n\nJSON raporu:\n{json_path}\n\nHTML raporunu açmak ister misiniz?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self.open_latest_report()

    @Slot()
    def open_latest_report(self) -> None:
        if self._latest_html_report and self._latest_html_report.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._latest_html_report.resolve())))
            return
        self._latest_html_report = None
        self.open_report_button.setEnabled(False)
        QMessageBox.warning(self, "Rapor bulunamadı", "Son oluşturulan HTML raporu artık bu konumda değil.")

    @Slot()
    def start_package(self) -> None:
        if not self.scan_result:
            return
        output_parent = QFileDialog.getExistingDirectory(self, "Çıktının oluşturulacağı klasörü seç")
        if not output_parent:
            return
        self._set_busy(
            True,
            "Temiz paket hazırlanıyor…",
            "Seçilen yollar çıkarılıyor, temiz kopya yeniden taranıyor ve raporlar oluşturuluyor.",
        )
        self.status_label.setText("Kaynak klasöre dokunulmadan yeni paket hazırlanıyor…")
        worker = PackageWorker(self.scan_result, Path(output_parent), self._checked_exclusions())
        worker.signals.finished.connect(self.package_finished)
        worker.signals.failed.connect(self.operation_failed)
        self.thread_pool.start(worker)

    @Slot(object)
    def package_finished(self, package: object) -> None:
        self._latest_html_report = Path(package.html_report)  # type: ignore[attr-defined]
        self._set_busy(
            False,
            "Temiz paket doğrulandı ve oluşturuldu",
            "İkinci taramada blocker kalmadı; ZIP, HTML/JSON raporu ve SHA-256 manifesti hazır.",
        )
        self.status_label.setText("Temiz paket başarıyla oluşturuldu.")
        output_dir = package.output_dir  # type: ignore[attr-defined]
        answer = QMessageBox.information(
            self,
            "Paket hazır",
            f"Temiz paket ve rapor oluşturuldu:\n{output_dir}\n\nHTML raporunu açmak ister misiniz?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self.open_latest_report()

    @Slot(str)
    def operation_failed(self, message: str) -> None:
        self._set_busy(False, "İşlem tamamlanamadı", "Ayrıntı için hata iletisini inceleyin.")
        self.spinner.fail()
        self.status_label.setText("İşlem başarısız.")
        QMessageBox.critical(self, "ShareGuard hatası", message)


def run_gui() -> int:
    if sys.platform.startswith("win"):
        os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
    app = QApplication(sys.argv)
    app.setApplicationName("ShareGuard")
    app.setOrganizationName("ShareGuard Project")
    window = MainWindow()
    window.show()
    return app.exec()
