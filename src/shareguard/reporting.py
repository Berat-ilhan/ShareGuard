from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from . import __version__
from .models import (
    ScanResult,
    redact_report_evidence,
    report_evidence_redactions,
    sanitize_report_data,
    sanitize_report_text,
)


SEVERITY_LABELS = {"blocker": "ENGEL", "review": "İNCELE", "info": "BİLGİ"}
VERDICT_LABELS = {"BLOCKED": "HAZIR DEĞİL", "REVIEW": "KONTROL GEREKİYOR", "READY": "HAZIR"}


def _html_text(value: object) -> str:
    return html.escape(sanitize_report_text(str(value)))


def _contains_raw_evidence(value: object, raw_values: tuple[str, ...]) -> bool:
    if isinstance(value, str):
        return any(raw in value for raw in raw_values)
    if isinstance(value, dict):
        return any(
            _contains_raw_evidence(key, raw_values)
            or _contains_raw_evidence(item, raw_values)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_raw_evidence(item, raw_values) for item in value)
    return False


def _assert_no_raw_evidence(value: object, redactions: tuple[tuple[str, str], ...]) -> None:
    raw_values = tuple(raw for raw, _masked in redactions)
    if raw_values and _contains_raw_evidence(value, raw_values):
        raise ValueError("Rapor yerel ham kanıt içerdiği için yazma işlemi durduruldu.")


def _human_size(byte_count: int) -> str:
    value = float(byte_count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{byte_count} B"


def _unique_report_paths(output_parent: Path) -> tuple[Path, Path]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = f"ShareGuard_Rapor_{timestamp}"
    suffix = 0
    while True:
        candidate = stem if suffix == 0 else f"{stem}_{suffix}"
        html_path = output_parent / f"{candidate}.html"
        json_path = output_parent / f"{candidate}.json"
        if not html_path.exists() and not json_path.exists():
            return html_path, json_path
        suffix += 1


def write_scan_report_bundle(output_parent: Path | str, source_scan: ScanResult) -> tuple[Path, Path]:
    """Write a standalone HTML/JSON scan report without creating a clean package."""

    destination = Path(output_parent).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    html_path, json_path = _unique_report_paths(destination)
    write_json_report(json_path, source_scan, clean_scan=None, excluded=())
    write_html_report(html_path, source_scan, clean_scan=None, excluded=())
    return html_path, json_path


def write_json_report(path: Path, source_scan: ScanResult, clean_scan: ScanResult | None, excluded: Iterable[str]) -> None:
    all_findings = list(source_scan.findings)
    if clean_scan:
        all_findings.extend(clean_scan.findings)
    redactions = report_evidence_redactions(all_findings)
    payload = {
        "schema_version": 1,
        "app_version": __version__,
        "source_scan": source_scan.to_dict(),
        "clean_scan": clean_scan.to_dict() if clean_scan else None,
        "excluded_paths": sorted(set(excluded)),
        "privacy_note": "Secret değerleri raporda maskelenmiştir.",
    }
    safe_payload = sanitize_report_data(redact_report_evidence(payload, redactions))
    _assert_no_raw_evidence(safe_payload, redactions)
    path.write_text(
        json.dumps(safe_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def write_html_report(path: Path, source_scan: ScanResult, clean_scan: ScanResult | None, excluded: Iterable[str]) -> None:
    all_findings = list(source_scan.findings)
    if clean_scan:
        all_findings.extend(clean_scan.findings)
    redactions = report_evidence_redactions(all_findings)

    def report_html_text(value: object) -> str:
        return _html_text(redact_report_evidence(str(value), redactions))

    rows: list[str] = []
    for finding in source_scan.sorted_findings():
        evidence = report_html_text(finding.masked_evidence or "-")
        location = report_html_text(finding.relative_path)
        if finding.line_number:
            location += f":{finding.line_number}"
        rows.append(
            "<tr>"
            f"<td data-label='Seviye'><span class='badge {finding.severity.value}'>{SEVERITY_LABELS[finding.severity.value]}</span></td>"
            f"<td data-label='Kimlik'>{report_html_text(finding.finding_id)}</td>"
            f"<td data-label='Konum'>{location}</td>"
            f"<td data-label='Açıklama'><strong>{report_html_text(finding.title)}</strong><br><small>{report_html_text(finding.explanation)}</small></td>"
            f"<td data-label='Maskeli kanıt'><code>{evidence}</code></td>"
            "</tr>"
        )
    excluded_items = "".join(
        f"<li>{report_html_text(item)}</li>" for item in sorted(set(excluded))
    ) or "<li>Yok</li>"
    clean_summary = "Henüz temiz paket oluşturulmadı."
    if clean_scan:
        clean_verdict = VERDICT_LABELS.get(clean_scan.verdict, clean_scan.verdict)
        clean_summary = (
            f"İkinci tarama sonucu: <strong>{report_html_text(clean_verdict)}</strong> — "
            f"{len(clean_scan.blockers)} blocker, {len(clean_scan.reviews)} inceleme, {len(clean_scan.infos)} bilgi."
        )
    project_name = source_scan.root.name or "Seçilen klasör"
    source_verdict = VERDICT_LABELS.get(source_scan.verdict, source_scan.verdict)
    scanned_at = source_scan.scanned_at or "Bilinmiyor"
    error_items = "".join(f"<li>{report_html_text(item)}</li>" for item in source_scan.errors)
    if not error_items:
        error_items = "<li>Okuma veya tarama hatası kaydedilmedi.</li>"
    document = f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>ShareGuard Denetim Raporu</title>
<style>
*,*::before,*::after{{box-sizing:border-box}}
body{{font-family:Segoe UI,Arial,sans-serif;background:#f4f6fa;color:#172033;margin:0;padding:32px}}
.wrap{{width:100%;max-width:1180px;margin:auto;min-width:0}} .card{{background:white;border-radius:14px;padding:24px;margin:16px 0;box-shadow:0 5px 20px #17203312;min-width:0}}
h1,h2{{margin-top:0}} .summary{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}
.metric{{padding:16px;border:1px solid #e4e8f0;border-radius:10px}} .metric b{{font-size:28px;display:block}}
.table-wrap{{width:100%;max-width:100%;overflow:hidden}}
.findings-table{{width:100%;max-width:100%;table-layout:fixed;border-collapse:collapse}}
.findings-table th,.findings-table td{{text-align:left;padding:11px;border-bottom:1px solid #e7eaf0;vertical-align:top;min-width:0;overflow-wrap:anywhere;word-break:normal}}
.badge{{display:inline-block;white-space:nowrap;overflow-wrap:normal;word-break:normal;font-size:11px;font-weight:600;padding:4px 6px;border-radius:4px}} .blocker{{background:#fee2e2;color:#991b1b}} .review{{background:#fef3c7;color:#92400e}} .info{{background:#ededeb;color:#50545a}}
code{{display:block;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}} small{{color:#5f6b7c}} .notice{{border-left:4px solid #2563eb;padding-left:12px}}
.identity{{display:flex;gap:28px;flex-wrap:wrap;color:#445168;overflow-wrap:anywhere}} .identity strong{{color:#172033}}
@media(max-width:800px){{
body{{padding:12px}} .card{{padding:18px}} .summary{{grid-template-columns:1fr 1fr}}
.findings-table,.findings-table tbody,.findings-table tr{{display:block;width:100%}}
.findings-table colgroup,.findings-table thead{{display:none}}
.findings-table tr{{padding:8px 0;border-bottom:1px solid #d9deea}}
.findings-table tr:last-child{{border-bottom:0}}
.findings-table td{{display:block;width:100%;padding:7px 0;border:0}}
.findings-table td::before{{content:attr(data-label);display:block;margin-bottom:4px;font-weight:700;color:#445168}}
}}
@media(max-width:480px){{.summary{{grid-template-columns:1fr}} .findings-table td{{grid-template-columns:1fr;gap:4px}}}}
</style></head><body><div class="wrap">
<h1>ShareGuard Denetim Raporu</h1>
<p><small>ShareGuard {report_html_text(__version__)}</small></p>
<p class="notice">Bu rapor mutlak güvenlik garantisi değildir. Tespit edilen hassas değerler maskelenmiştir.</p>
<div class="card"><h2>Tarama bilgisi</h2><div class="identity">
<span><strong>Proje:</strong> {report_html_text(project_name)}</span>
<span><strong>Tarama zamanı (UTC):</strong> {report_html_text(scanned_at)}</span>
</div></div>
<div class="card"><h2>Özet</h2><div class="summary">
<div class="metric"><b>{report_html_text(source_verdict)}</b>Kaynak sonucu</div>
<div class="metric"><b>{len(source_scan.blockers)}</b>Blocker</div>
<div class="metric"><b>{len(source_scan.reviews)}</b>İncelenmeli</div>
<div class="metric"><b>{source_scan.stats.files_seen}</b>Taranan dosya</div>
<div class="metric"><b>{source_scan.stats.directories_seen}</b>Taranan dizin</div>
<div class="metric"><b>{report_html_text(_human_size(source_scan.stats.bytes_seen))}</b>Toplam boyut</div>
<div class="metric"><b>{source_scan.stats.skipped_items}</b>Atlanan öğe</div>
<div class="metric"><b>{source_scan.stats.errors}</b>Okuma/tarama hatası</div>
</div><p>{clean_summary}</p></div>
<div class="card"><h2>Bulgular</h2><div class="table-wrap"><table class="findings-table"><colgroup>
<col style="width:10%"><col style="width:9%"><col style="width:27%"><col style="width:36%"><col style="width:18%">
</colgroup><thead><tr><th>Seviye</th><th>Kimlik</th><th>Konum</th><th>Açıklama</th><th>Maskeli kanıt</th></tr></thead><tbody>
{''.join(rows) if rows else '<tr><td colspan="5">Bulgu yok.</td></tr>'}
</tbody></table></div></div>
<div class="card"><h2>Okuma ve tarama hataları</h2><ul>{error_items}</ul></div>
<div class="card"><h2>Temiz paketten çıkarılanlar</h2><ul>{excluded_items}</ul></div>
<div class="card"><h2>Sınırlamalar</h2><ul>
<li>Şifreli, desteklenmeyen veya okuma hatası veren içerik güvenli kabul edilmez.</li>
<li>İlk sürüm Git geçmişini taramaz; yalnız çalışma klasörünü tarar.</li>
<li>İlk sürüm PDF metadata bilgisini raporlar fakat otomatik silmez.</li>
<li>Regex tabanlı kişisel veri tespiti yanlış pozitif ve yanlış negatif üretebilir.</li>
</ul></div></div></body></html>"""
    _assert_no_raw_evidence(html.unescape(document), redactions)
    path.write_text(document, encoding="utf-8")
