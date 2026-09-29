from __future__ import annotations

import os
import stat
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Callable

from .detectors import (
    DetectorConfig,
    FindingFactory,
    HygieneDetector,
    MetadataDetector,
    TextDetector,
    TextInspectionIncomplete,
)
from .models import Finding, RecommendedAction, ScanResult, ScanStats, Severity


ProgressCallback = Callable[[str, int], None]


def _safe_os_error(exc: OSError) -> str:
    """Describe an OS error without copying an absolute local path into reports."""

    message = exc.strerror or exc.__class__.__name__
    return f"errno {exc.errno}: {message}" if exc.errno is not None else message


def _safe_relative_error_path(filename: object, root: Path) -> str:
    """Return a report-safe path, never an absolute path outside the root."""

    if not filename:
        return "(bilinmeyen dizin)"
    raw_filename = str(filename)
    candidate = Path(raw_filename)
    windows_candidate = PureWindowsPath(raw_filename)
    if windows_candidate.is_absolute() and not candidate.is_absolute():
        return windows_candidate.name or "(bilinmeyen dizin)"
    try:
        relative = candidate.relative_to(root) if candidate.is_absolute() else candidate
    except ValueError:
        return candidate.name or "(bilinmeyen dizin)"
    safe_parts = [part for part in relative.parts if part not in {"", ".", ".."}]
    return Path(*safe_parts).as_posix() if safe_parts else "."


def _is_link_or_reparse(path: Path) -> bool:
    """Detect symlinks and Windows junctions without following their target."""

    file_info = path.lstat()
    if stat.S_ISLNK(file_info.st_mode):
        return True
    attributes = getattr(file_info, "st_file_attributes", 0)
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


class FolderScanner:
    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()

    def scan(self, root: Path | str, progress: ProgressCallback | None = None) -> ScanResult:
        root_path = Path(root).expanduser().resolve()
        if not root_path.is_dir():
            raise ValueError(f"Taranacak klasör bulunamadı: {root_path}")

        factory = FindingFactory()
        hygiene = HygieneDetector(factory, self.config)
        text = TextDetector(factory, self.config)
        metadata = MetadataDetector(factory)
        result = ScanResult(
            root=root_path,
            stats=ScanStats(),
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )

        def incomplete_finding(relative_path: str, reason: str, *, directory: bool = False) -> Finding:
            target = "Dizin" if directory else "Dosya"
            return factory.make(
                severity=Severity.REVIEW,
                category="eksik-tarama",
                relative_path=relative_path,
                title="İçerik tam taranamadı",
                explanation=f"{target} içeriğinin tamamı denetlenemedi: {reason}",
                detector="coverage",
                recommended_action=RecommendedAction.REVIEW,
            )

        def on_walk_error(exc: OSError) -> None:
            relative = _safe_relative_error_path(exc.filename, root_path)
            safe_error = _safe_os_error(exc)
            result.stats.errors += 1
            result.stats.skipped_items += 1
            result.errors.append(f"Dizin taranamadı: {relative}: {safe_error}")
            result.findings.append(incomplete_finding(relative, safe_error, directory=True))

        for current, directories, files in os.walk(
            root_path,
            topdown=True,
            onerror=on_walk_error,
            followlinks=False,
        ):
            current_path = Path(current)
            result.stats.directories_seen += 1
            kept_directories: list[str] = []
            for directory in sorted(directories):
                absolute = current_path / directory
                relative = absolute.relative_to(root_path).as_posix()
                try:
                    is_link_or_reparse = _is_link_or_reparse(absolute)
                except OSError as exc:
                    safe_error = _safe_os_error(exc)
                    result.stats.errors += 1
                    result.stats.skipped_items += 1
                    result.errors.append(f"Dizin bilgisi okunamadı: {relative}: {safe_error}")
                    result.findings.append(incomplete_finding(relative, safe_error, directory=True))
                    continue
                if is_link_or_reparse:
                    result.stats.skipped_items += 1
                    result.errors.append(f"Bağlantı veya reparse noktası atlandı: {relative}")
                    continue
                finding = hygiene.inspect_directory(relative, directory)
                if finding:
                    result.findings.append(finding)
                    result.stats.skipped_items += 1
                    continue
                kept_directories.append(directory)
            directories[:] = kept_directories

            for filename in sorted(files):
                path = current_path / filename
                relative = path.relative_to(root_path).as_posix()
                try:
                    file_info = path.lstat()
                    is_link_or_reparse = (
                        stat.S_ISLNK(file_info.st_mode)
                        or bool(
                            getattr(file_info, "st_file_attributes", 0)
                            & stat.FILE_ATTRIBUTE_REPARSE_POINT
                        )
                    )
                except OSError as exc:
                    safe_error = _safe_os_error(exc)
                    result.stats.errors += 1
                    result.stats.skipped_items += 1
                    result.errors.append(f"Dosya bilgisi okunamadı: {relative}: {safe_error}")
                    result.findings.append(incomplete_finding(relative, safe_error))
                    continue
                if is_link_or_reparse:
                    result.stats.skipped_items += 1
                    result.errors.append(f"Bağlantı veya reparse noktası atlandı: {relative}")
                    continue
                size = file_info.st_size

                result.stats.files_seen += 1
                result.stats.bytes_seen += size
                if progress:
                    progress(relative, result.stats.files_seen)
                try:
                    result.findings.extend(hygiene.inspect_file(path, relative, size))
                except OSError as exc:
                    result.stats.errors += 1
                    result.errors.append(f"Dosya taranamadı: {relative}: {_safe_os_error(exc)}")

                if text.supports(path):
                    try:
                        result.findings.extend(text.inspect(path, relative))
                    except TextInspectionIncomplete as exc:
                        result.stats.skipped_items += 1
                        result.findings.append(incomplete_finding(relative, exc.reason))
                    except OSError as exc:
                        safe_error = _safe_os_error(exc)
                        result.stats.errors += 1
                        result.stats.skipped_items += 1
                        result.errors.append(
                            f"Dosya içeriği okunamadı: {relative}: {safe_error}"
                        )
                        result.findings.append(incomplete_finding(relative, safe_error))

                try:
                    result.findings.extend(metadata.inspect(path, relative))
                except OSError as exc:
                    result.stats.errors += 1
                    result.errors.append(f"Dosya taranamadı: {relative}: {_safe_os_error(exc)}")

        return result
