from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .detectors import JUNK_DIRECTORIES
from .models import PackagingResult, ScanResult, unique_paths
from .reporting import write_html_report, write_json_report
from .scanner import FolderScanner


class UnsafePackageError(RuntimeError):
    pass


_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


def _is_link_or_reparse_point(path: Path) -> bool:
    """Treat POSIX links and Windows reparse points as non-copyable entries.

    ``os.walk(..., followlinks=False)`` does not reliably prune every Windows
    junction. ``lstat`` exposes those entries through ``st_file_attributes``.
    If metadata changes or becomes unreadable during the copy, fail closed and
    skip the entry instead of risking traversal outside the selected root.
    """

    try:
        metadata = path.lstat()
    except OSError:
        return True
    return stat.S_ISLNK(getattr(metadata, "st_mode", 0)) or bool(
        getattr(metadata, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _mandatory_exclusions(source_scan: ScanResult) -> tuple[str, ...]:
    """Return directories that were deliberately not inspected recursively.

    A directory cannot be presented as safely re-scanned when the scanner
    intentionally skipped its contents. These paths are therefore excluded at
    the core packaging layer, even if a UI/client omits them.
    """

    return unique_paths(
        finding.relative_path
        for finding in source_scan.findings
        if finding.category == "gereksiz-dizin"
    )


def _is_excluded(relative_path: str, excluded: tuple[str, ...]) -> bool:
    normalized = Path(relative_path).as_posix().strip("/")
    return any(normalized == item or normalized.startswith(item + "/") for item in excluded)


def _copy_tree(source: Path, destination: Path, excluded: tuple[str, ...]) -> tuple[str, ...]:
    mandatory_exclusions: list[str] = []
    destination.mkdir(parents=True, exist_ok=False)
    for current, directories, files in os.walk(source, topdown=True, followlinks=False):
        current_path = Path(current)
        relative_dir = current_path.relative_to(source)
        kept: list[str] = []
        for directory in sorted(directories):
            source_dir = current_path / directory
            relative = (relative_dir / directory).as_posix()
            if _is_link_or_reparse_point(source_dir):
                mandatory_exclusions.append(relative)
                continue
            if directory.lower() in JUNK_DIRECTORIES:
                mandatory_exclusions.append(relative)
                continue
            if _is_excluded(relative, excluded):
                continue
            (destination / relative).mkdir(parents=True, exist_ok=True)
            kept.append(directory)
        directories[:] = kept
        for filename in sorted(files):
            source_file = current_path / filename
            relative = (relative_dir / filename).as_posix()
            if _is_link_or_reparse_point(source_file):
                mandatory_exclusions.append(relative)
                continue
            if _is_excluded(relative, excluded):
                continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target)
    return unique_paths(mandatory_exclusions)


def _reserve_output_path(output_root: Path, timestamp: str) -> tuple[Path, Path]:
    """Atomically reserve a unique final output name with an adjacent lock file."""

    suffix = 0
    while True:
        suffix_text = f"_{suffix}" if suffix else ""
        name = f"ShareGuard_Output_{timestamp}{suffix_text}"
        final_dir = output_root / name
        reservation = output_root / f".{name}.reserve"
        try:
            descriptor = os.open(reservation, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            suffix += 1
            continue
        else:
            os.close(descriptor)

        # A completed package may predate the reservation protocol. Keep its
        # name occupied and retry while still holding our unique reservation.
        if os.path.lexists(final_dir):
            try:
                reservation.unlink()
            except FileNotFoundError:
                pass
            suffix += 1
            continue
        return final_dir, reservation


def _write_manifest(clean_dir: Path, destination: Path) -> None:
    lines: list[str] = []
    for path in sorted(item for item in clean_dir.rglob("*") if item.is_file() and not item.is_symlink()):
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        lines.append(f"{digest.hexdigest()}  {path.relative_to(clean_dir).as_posix()}")
    destination.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _write_zip(clean_dir: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(item for item in clean_dir.rglob("*") if item.is_file() and not item.is_symlink()):
            archive.write(path, arcname=path.relative_to(clean_dir).as_posix())


class SafePackager:
    def __init__(self, scanner: FolderScanner | None = None) -> None:
        self.scanner = scanner or FolderScanner()

    def build(
        self,
        source_scan: ScanResult,
        output_parent: Path | str,
        excluded_paths: Iterable[str],
    ) -> PackagingResult:
        source = source_scan.root.resolve()
        output_root = Path(output_parent).expanduser().resolve()
        if output_root == source or source in output_root.parents:
            raise ValueError("Çıktı klasörü kaynak klasörün içinde olamaz.")

        # The scan supplied by the caller is useful for selecting a source, but
        # it may already be stale by the time packaging starts. Security
        # decisions and reports must describe a scan performed for this build.
        current_source_scan = self.scanner.scan(source)
        requested_exclusions = list(excluded_paths)
        excluded = unique_paths((*requested_exclusions, *_mandatory_exclusions(current_source_scan)))

        unresolved = [
            item for item in current_source_scan.blockers if not _is_excluded(item.relative_path, excluded)
        ]
        if unresolved:
            locations = ", ".join(sorted({item.relative_path for item in unresolved}))
            raise UnsafePackageError(f"Çıkarılmamış blocker bulundu: {locations}")

        output_root.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        final_dir, reservation = _reserve_output_path(output_root, timestamp)
        try:
            with tempfile.TemporaryDirectory(prefix="shareguard-stage-", dir=output_root) as temporary:
                stage_root = Path(temporary)
                stage_clean = stage_root / "clean-package"
                copied_exclusions = _copy_tree(source, stage_clean, excluded)
                excluded = unique_paths((*excluded, *copied_exclusions))
                clean_scan = self.scanner.scan(stage_clean)
                if clean_scan.errors or clean_scan.stats.errors:
                    error_count = max(len(clean_scan.errors), clean_scan.stats.errors)
                    raise UnsafePackageError(
                        "İkinci tarama tamamlanamadı; "
                        f"{error_count} okuma hatası bulundu."
                    )
                if clean_scan.blockers:
                    locations = ", ".join(sorted({item.relative_path for item in clean_scan.blockers}))
                    raise UnsafePackageError(f"İkinci taramada blocker kaldı: {locations}")

                stage_final = stage_root / "final"
                stage_final.mkdir()
                clean_dir = stage_final / "clean-package"
                shutil.move(str(stage_clean), clean_dir)
                manifest = stage_final / "manifest.sha256"
                excluded_file = stage_final / "paketten-cikarilanlar.txt"
                json_report = stage_final / "bulgular.json"
                html_report = stage_final / "SHAREGUARD-RAPORU.html"
                zip_path = stage_final / "temiz-paket.zip"

                _write_manifest(clean_dir, manifest)
                excluded_file.write_text("\n".join(excluded) + ("\n" if excluded else ""), encoding="utf-8")
                write_json_report(json_report, current_source_scan, clean_scan, excluded)
                write_html_report(html_report, current_source_scan, clean_scan, excluded)
                _write_zip(clean_dir, zip_path)

                # The stage directory and destination share a filesystem, so
                # rename publishes the fully built package in one operation.
                stage_final.rename(final_dir)
        finally:
            try:
                reservation.unlink()
            except FileNotFoundError:
                pass

        return PackagingResult(
            output_dir=final_dir,
            clean_dir=final_dir / "clean-package",
            zip_path=final_dir / "temiz-paket.zip",
            html_report=final_dir / "SHAREGUARD-RAPORU.html",
            json_report=final_dir / "bulgular.json",
            manifest_path=final_dir / "manifest.sha256",
            excluded_path=final_dir / "paketten-cikarilanlar.txt",
            excluded=excluded,
            clean_scan=clean_scan,
        )
