from __future__ import annotations

import ipaddress
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree

from .models import Finding, RecommendedAction, Severity


TEXT_EXTENSIONS = {
    ".txt", ".md", ".rst", ".py", ".js", ".ts", ".tsx", ".jsx",
    ".java", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".go",
    ".rs", ".php", ".rb", ".sh", ".ps1", ".bat", ".cmd", ".xml",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".env", ".csv", ".sql", ".log", ".html", ".css",
    ".pem", ".gradle", ".kt", ".kts",
}

TEXT_FILENAMES = {
    "dockerfile", "makefile", "gnumakefile", ".npmrc", ".yarnrc",
    ".editorconfig", ".gitignore", ".gitattributes", ".dockerignore",
    ".eslintignore", ".eslintrc", ".prettierignore", ".prettierrc",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity",
}

JUNK_DIRECTORIES = {
    "node_modules", ".venv", "venv", "env", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", ".nox", "dist", "build",
    "target", ".gradle", ".idea", ".vs", ".git",
}

JUNK_FILES = {"thumbs.db", ".ds_store", "desktop.ini"}


@dataclass(frozen=True)
class DetectorConfig:
    max_text_bytes: int = 2 * 1024 * 1024
    large_file_bytes: int = 25 * 1024 * 1024


def mask_value(value: str, prefix: int = 4, suffix: int = 3) -> str:
    compact = value.strip().strip("'\"")
    if len(compact) < 16:
        return "*" * max(4, len(compact))
    # Never expose most of a medium-sized value merely because the caller
    # requested a generous prefix/suffix (for example an IP address or email).
    visible_budget = max(2, len(compact) // 4)
    visible_prefix = min(prefix, (visible_budget + 1) // 2)
    visible_suffix = min(suffix, visible_budget - visible_prefix)
    hidden = max(8, len(compact) - visible_prefix - visible_suffix)
    return f"{compact[:visible_prefix]}{'*' * hidden}{compact[-visible_suffix:] if visible_suffix else ''}"


class FindingFactory:
    def __init__(self) -> None:
        self._counter = 0

    def make(self, **kwargs: object) -> Finding:
        self._counter += 1
        return Finding(finding_id=f"SG-{self._counter:04d}", **kwargs)  # type: ignore[arg-type]


class TextInspectionIncomplete(Exception):
    """The file is text-like, but it could not be scanned completely."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class HygieneDetector:
    def __init__(self, factory: FindingFactory, config: DetectorConfig) -> None:
        self.factory = factory
        self.config = config

    def inspect_directory(self, relative_path: str, name: str) -> Finding | None:
        if name.lower() not in JUNK_DIRECTORIES:
            return None
        return self.factory.make(
            severity=Severity.INFO,
            category="gereksiz-dizin",
            relative_path=relative_path,
            title="Teslim paketinde genellikle gereksiz dizin",
            explanation=(
                "Bağımlılık, önbellek, derleme çıktısı veya sürüm kontrol verisi olabilir. "
                "Temiz paketten çıkarılması önerilir."
            ),
            detector="hygiene",
            recommended_action=RecommendedAction.EXCLUDE,
        )

    def inspect_file(self, path: Path, relative_path: str, size: int) -> Iterable[Finding]:
        lower_name = path.name.lower()
        if lower_name in JUNK_FILES or path.suffix.lower() in {".pyc", ".pyo", ".tmp", ".bak", ".swp"}:
            yield self.factory.make(
                severity=Severity.INFO,
                category="gereksiz-dosya",
                relative_path=relative_path,
                title="Geçici veya sistem tarafından üretilen dosya",
                explanation="Bu dosya teslim paketinin çalışması için genellikle gerekli değildir.",
                detector="hygiene",
                recommended_action=RecommendedAction.EXCLUDE,
            )

        if lower_name == ".env" or lower_name.startswith(".env."):
            yield self.factory.make(
                severity=Severity.BLOCKER,
                category="ortam-dosyasi",
                relative_path=relative_path,
                title="Ortam değişkeni dosyası",
                explanation="Bu dosya parola, token veya servis bağlantı bilgileri içerebilir.",
                detector="hygiene",
                recommended_action=RecommendedAction.EXCLUDE,
            )

        if path.suffix.lower() in {".p12", ".pfx", ".key", ".kdbx"}:
            yield self.factory.make(
                severity=Severity.BLOCKER,
                category="anahtar-dosyasi",
                relative_path=relative_path,
                title="Özel anahtar veya kimlik bilgisi dosyası olabilir",
                explanation="Dosya türü kriptografik anahtar ya da parola kasası taşıyabilir.",
                detector="hygiene",
                recommended_action=RecommendedAction.EXCLUDE,
            )

        if path.suffix.lower() == ".pem":
            yield self.factory.make(
                severity=Severity.REVIEW,
                category="pem-dosyasi",
                relative_path=relative_path,
                title="PEM kodlu sertifika veya anahtar dosyası",
                explanation=(
                    "PEM uzantısı tek başına özel anahtar kanıtı değildir. İçerikte PRIVATE KEY "
                    "başlığı varsa ayrıca engelleyici bulgu üretilir; yalnız sertifikaysa insan "
                    "tarafından gerekli olup olmadığı doğrulanmalıdır."
                ),
                detector="hygiene",
                recommended_action=RecommendedAction.REVIEW,
            )

        if path.suffix.lower() in {".db", ".sqlite", ".sqlite3", ".sql", ".dump", ".log"}:
            yield self.factory.make(
                severity=Severity.REVIEW,
                category="veri-dosyasi",
                relative_path=relative_path,
                title="Kullanıcı veya çalışma verisi içerebilecek dosya",
                explanation="Paket için gerekli olup olmadığı ve kişisel veri içerip içermediği incelenmelidir.",
                detector="hygiene",
                recommended_action=RecommendedAction.REVIEW,
            )

        if path.suffix.lower() in {".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1"}:
            yield self.factory.make(
                severity=Severity.REVIEW,
                category="calistirilabilir-dosya",
                relative_path=relative_path,
                title="Çalıştırılabilir veya komut dosyası",
                explanation="Teslim paketine bilinçli olarak eklendiği doğrulanmalıdır.",
                detector="hygiene",
                recommended_action=RecommendedAction.REVIEW,
            )

        if size >= self.config.large_file_bytes:
            yield self.factory.make(
                severity=Severity.REVIEW,
                category="buyuk-dosya",
                relative_path=relative_path,
                title="Büyük dosya",
                explanation=f"Dosya boyutu {size / (1024 * 1024):.1f} MiB; pakete dahil edilmesi doğrulanmalıdır.",
                detector="hygiene",
                recommended_action=RecommendedAction.REVIEW,
            )


class TextDetector:
    ASSIGNED_SECRET_RE = re.compile(
        r"(?ix)"
        r"(?<![A-Za-z0-9])"
        r"(?:[A-Za-z][A-Za-z0-9]*[_-])*"
        r"(?:api[_-]?key|client[_-]?secret|secret(?:[_-]?key)?|"
        r"auth[_-]?token|access[_-]?token|token|password|passwd|pwd)"
        r"(?:[_-][A-Za-z][A-Za-z0-9]*)*"
        r"(?![A-Za-z0-9_])"
        r"\s*(?::(?!:)|=(?!=))\s*"
        r"(?:"
        r"(?P<quote>['\"])(?P<quoted>[^'\"\r\n]{8,})(?P=quote)"
        r"|(?P<bare>[A-Za-z0-9_./+~=:@%-]{12,})"
        r")"
    )
    SECRET_PATTERNS = (
        ("ozel-anahtar", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), "Özel anahtar başlangıcı"),
        ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS erişim anahtarı biçimi"),
        ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"), "GitHub token biçimi"),
        ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "JWT biçimi"),
        ("atanmis-secret", ASSIGNED_SECRET_RE, "Kod içine yazılmış kimlik bilgisi adayı"),
    )
    EMAIL_RE = re.compile(r"(?<![\w.+-])([\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.-])")
    IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
    PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d ()-]{8,}\d)(?!\d)")
    PHONE_CONTEXT_RE = re.compile(r"(?i)\b(?:phone|telephone|mobile|cell|tel|gsm|whatsapp|contact|telefon)\b")
    IP_CONTEXT_RE = re.compile(r"(?i)\b(?:ip|host|server|proxy|address|endpoint|gateway|dns)\b")

    def __init__(self, factory: FindingFactory, config: DetectorConfig) -> None:
        self.factory = factory
        self.config = config
        self._seen_pii_values: set[tuple[str, str, str]] = set()

    def supports(self, path: Path) -> bool:
        lower_name = path.name.lower()
        return (
            path.suffix.lower() in TEXT_EXTENSIONS
            or lower_name in TEXT_FILENAMES
            or (not path.suffix and lower_name.startswith("id_"))
            or lower_name.startswith(".env")
            or lower_name.startswith("dockerfile.")
        )

    def inspect(self, path: Path, relative_path: str) -> Iterable[Finding]:
        # Do not catch OSError here. The scanner must account for an unreadable
        # supported text file instead of silently treating the scan as complete.
        with path.open("rb") as handle:
            raw = handle.read(self.config.max_text_bytes + 1)
        if len(raw) > self.config.max_text_bytes:
            limit_mib = self.config.max_text_bytes / (1024 * 1024)
            raise TextInspectionIncomplete(
                f"Dosya {limit_mib:g} MiB metin tarama sınırını aşıyor."
            )

        text = self._decode_text(raw)

        seen_secret_lines: set[tuple[str, int]] = set()
        for line_number, line in enumerate(text.splitlines(), start=1):
            for category, pattern, title in self.SECRET_PATTERNS:
                match = pattern.search(line)
                if not match or (category, line_number) in seen_secret_lines:
                    continue
                if category == "atanmis-secret":
                    value = match.group("quoted") or match.group("bare")
                    if match.group("bare") and not self._plausible_bare_secret(value):
                        continue
                else:
                    value = match.group(0)
                seen_secret_lines.add((category, line_number))
                yield self.factory.make(
                    severity=Severity.BLOCKER,
                    category=category,
                    relative_path=relative_path,
                    title=title,
                    explanation=(
                        "Tam değer yalnız yerel uygulamada gösterilir; kaydedilen raporda "
                        "maskelenir. Dosya paylaşılmadan önce anahtar kaldırılmalı veya "
                        "iptal edilmelidir."
                    ),
                    detector="text-secret",
                    recommended_action=RecommendedAction.EXCLUDE,
                    line_number=line_number,
                    masked_evidence=mask_value(value),
                    local_evidence=value,
                )

            for email in self.EMAIL_RE.findall(line):
                if email.lower().endswith(("@example.com", "@example.org", "@example.net")):
                    continue
                if not self._first_pii_occurrence("e-posta", relative_path, email.casefold()):
                    continue
                yield self.factory.make(
                    severity=Severity.REVIEW,
                    category="e-posta",
                    relative_path=relative_path,
                    title="E-posta adresi adayı",
                    explanation="Kişisel veya kurumsal iletişim bilgisi olabilir.",
                    detector="text-pii",
                    recommended_action=RecommendedAction.REVIEW,
                    line_number=line_number,
                    masked_evidence=mask_value(email, 2, 5),
                    local_evidence=email,
                )

            for candidate in dict.fromkeys(self.IPV4_RE.findall(line)):
                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
                    continue
                if not address.is_private and not self.IP_CONTEXT_RE.search(line):
                    continue
                if not self._first_pii_occurrence("ip-adresi", relative_path, candidate):
                    continue
                yield self.factory.make(
                    severity=Severity.REVIEW,
                    category="ip-adresi",
                    relative_path=relative_path,
                    title="IP adresi adayı",
                    explanation="İç ağ veya kullanıcı altyapısı hakkında bilgi verebilir.",
                    detector="text-pii",
                    recommended_action=RecommendedAction.REVIEW,
                    line_number=line_number,
                    masked_evidence=mask_value(candidate, 3, 3),
                    local_evidence=candidate,
                )

            for phone in dict.fromkeys(self.PHONE_RE.findall(line)):
                digits = re.sub(r"\D", "", phone)
                if not 10 <= len(digits) <= 15 or not self._plausible_phone(phone, line):
                    continue
                if not self._first_pii_occurrence("telefon", relative_path, digits):
                    continue
                yield self.factory.make(
                    severity=Severity.REVIEW,
                    category="telefon",
                    relative_path=relative_path,
                    title="Telefon numarası adayı",
                    explanation="Kişisel iletişim bilgisi olabilir; yanlış pozitif ihtimali vardır.",
                    detector="text-pii",
                    recommended_action=RecommendedAction.REVIEW,
                    line_number=line_number,
                    masked_evidence=mask_value(digits, 2, 2),
                    local_evidence=phone,
                )

    @classmethod
    def _decode_text(cls, raw: bytes) -> str:
        """Decode likely text without silently accepting binary input.

        UTF BOMs are authoritative. For BOM-less legacy text, Windows single-
        byte codecs preserve ASCII secret markers while control-byte checks
        keep obvious binary data out of the text detector.
        """

        bom_encodings = (
            (b"\x00\x00\xfe\xff", "utf-32"),
            (b"\xff\xfe\x00\x00", "utf-32"),
            (b"\xfe\xff", "utf-16"),
            (b"\xff\xfe", "utf-16"),
        )
        for bom, encoding in bom_encodings:
            if raw.startswith(bom):
                try:
                    return raw.decode(encoding)
                except UnicodeDecodeError as exc:
                    raise TextInspectionIncomplete(
                        "Unicode BOM bulundu ancak içerik geçerli biçimde çözülemedi."
                    ) from exc

        if raw.startswith(b"\xef\xbb\xbf"):
            try:
                return raw.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise TextInspectionIncomplete(
                    "UTF-8 BOM bulundu ancak içerik geçerli biçimde çözülemedi."
                ) from exc

        if cls._looks_binary(raw):
            raise TextInspectionIncomplete(
                "Dosya NUL veya ikili veri göstergeleri içeriyor."
            )

        try:
            return raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            pass

        for encoding in ("cp1252", "cp1254"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue

        raise TextInspectionIncomplete("Dosya içeriğinin karakter kodlaması çözülemedi.")

    @staticmethod
    def _looks_binary(raw: bytes) -> bool:
        if b"\x00" in raw:
            return True
        if not raw:
            return False
        disallowed_controls = sum(
            byte < 32 and byte not in {9, 10, 12, 13} for byte in raw
        )
        return disallowed_controls > 0

    @staticmethod
    def _plausible_bare_secret(value: str) -> bool:
        """Reject identifiers/call expressions while retaining token-like literals."""

        lowered = value.casefold()
        placeholders = {
            "changeme", "change-me", "your-token-here", "your-api-key",
            "password", "secret", "example-token", "replace-me",
        }
        if lowered in placeholders:
            return False
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", value) and not any(
            character.isdigit() for character in value
        ):
            return False
        has_digit = any(character.isdigit() for character in value)
        has_symbol = any(not character.isalnum() and character != "_" for character in value)
        return len(value) >= 16 and (has_digit or has_symbol)

    def _plausible_phone(self, candidate: str, line: str) -> bool:
        compact = candidate.strip()
        if compact.startswith("+") or re.search(r"\(\d{2,4}\)", compact):
            return True
        if re.fullmatch(r"\d{3}[- ]\d{3}[- ]\d{4}", compact):
            return True
        return bool(self.PHONE_CONTEXT_RE.search(line) and re.search(r"[ ()-]", compact))

    def _first_pii_occurrence(self, category: str, relative_path: str, value: str) -> bool:
        key = (category, relative_path, value)
        if key in self._seen_pii_values:
            return False
        self._seen_pii_values.add(key)
        return True


class MetadataDetector:
    OFFICE_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
    CORE_NS = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    DCTERMS_NS = "http://purl.org/dc/terms/"
    DC_NS = "http://purl.org/dc/elements/1.1/"

    def __init__(self, factory: FindingFactory) -> None:
        self.factory = factory

    def inspect(self, path: Path, relative_path: str) -> Iterable[Finding]:
        suffix = path.suffix.lower()
        if suffix in self.OFFICE_EXTENSIONS:
            yield from self._inspect_office(path, relative_path)
        elif suffix == ".pdf":
            yield from self._inspect_pdf(path, relative_path)
        elif suffix in {".jpg", ".jpeg", ".tif", ".tiff", ".png", ".webp"}:
            yield from self._inspect_image(path, relative_path)

    def _inspect_office(self, path: Path, relative_path: str) -> Iterable[Finding]:
        try:
            with zipfile.ZipFile(path) as archive:
                info = archive.getinfo("docProps/core.xml")
                if info.file_size > 1024 * 1024:
                    return
                if info.compress_size and info.file_size / info.compress_size > 100:
                    return
                raw = archive.read("docProps/core.xml")
        except (OSError, KeyError, zipfile.BadZipFile):
            return
        try:
            root = ElementTree.fromstring(raw)
        except ElementTree.ParseError:
            return
        sensitive_tags = {
            f"{{{self.DC_NS}}}creator": "yazar",
            f"{{{self.CORE_NS}}}lastModifiedBy": "son düzenleyen",
            f"{{{self.CORE_NS}}}keywords": "anahtar kelimeler",
            f"{{{self.DC_NS}}}subject": "konu",
        }
        present = [label for tag, label in sensitive_tags.items() if (node := root.find(tag)) is not None and (node.text or "").strip()]
        if present:
            yield self.factory.make(
                severity=Severity.REVIEW,
                category="office-metadata",
                relative_path=relative_path,
                title="Office belgesinde kişisel metadata",
                explanation="Bulunan alan türleri: " + ", ".join(present) + ". Değerler rapora yazılmadı.",
                detector="metadata",
                recommended_action=RecommendedAction.REVIEW,
            )

    def _inspect_pdf(self, path: Path, relative_path: str) -> Iterable[Finding]:
        try:
            from pypdf import PdfReader
        except ImportError:
            return
        try:
            metadata = PdfReader(str(path), strict=False).metadata or {}
        except Exception:
            return
        keys = [key.lstrip("/") for key, value in metadata.items() if value and key in {"/Author", "/Creator", "/Producer", "/Subject", "/Keywords"}]
        if keys:
            yield self.factory.make(
                severity=Severity.REVIEW,
                category="pdf-metadata",
                relative_path=relative_path,
                title="PDF belgesinde metadata",
                explanation="Bulunan alan türleri: " + ", ".join(keys) + ". İlk sürüm PDF metadata'sını otomatik silmez.",
                detector="metadata",
                recommended_action=RecommendedAction.REVIEW,
            )

    def _inspect_image(self, path: Path, relative_path: str) -> Iterable[Finding]:
        try:
            from PIL import ExifTags, Image
        except ImportError:
            return
        try:
            with Image.open(path) as image:
                exif = image.getexif()
                names = {ExifTags.TAGS.get(tag, str(tag)) for tag in exif.keys()}
        except Exception:
            return
        sensitive = sorted(names.intersection({"GPSInfo", "Make", "Model", "Software", "Artist", "Copyright", "DateTimeOriginal"}))
        if sensitive:
            yield self.factory.make(
                severity=Severity.REVIEW,
                category="gorsel-metadata",
                relative_path=relative_path,
                title="Görselde paylaşım öncesi incelenecek metadata",
                explanation="Bulunan alan türleri: " + ", ".join(sensitive) + ". Değerler rapora yazılmadı.",
                detector="metadata",
                recommended_action=RecommendedAction.REVIEW,
            )
