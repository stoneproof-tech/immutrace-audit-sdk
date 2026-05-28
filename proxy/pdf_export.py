"""PDF export with chain-of-custody + QR verification."""
import sqlite3
import hashlib
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import qrcode
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image,
    KeepTogether,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from . import config
from .chain import verify_chain


def _qr_png(text: str) -> io.BytesIO:
    img = qrcode.make(text, box_size=4, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def _fetch_session_data(session_id: str) -> dict:
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        sess = cur.fetchone()
        if not sess:
            raise ValueError(f"Session {session_id} not found")
        cur = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY id ASC",
            (session_id,),
        )
        events = [dict(r) for r in cur.fetchall()]
        anchor_ids = sorted({e["anchor_id"] for e in events if e["anchor_id"]})
        anchors = []
        if anchor_ids:
            qmarks = ",".join("?" * len(anchor_ids))
            cur = conn.execute(
                f"SELECT * FROM anchors WHERE id IN ({qmarks}) ORDER BY id ASC",
                anchor_ids,
            )
            anchors = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return {"session": dict(sess), "events": events, "anchors": anchors}


def _mask_encrypted(v):
    """Never render ciphertext in the report: encrypted-at-rest values -> [ENCRYPTED]."""
    s = "" if v is None else str(v)
    return "[ENCRYPTED]" if s.startswith("enc:v1:") else s


def build_session_pdf(session_id: str) -> dict:
    """Render the audit PDF for one session. Returns {path, filename, sha256}."""
    data = _fetch_session_data(session_id)
    sess = data["session"]
    events = data["events"]
    anchors = data["anchors"]
    enc_count = sum(1 for e in events
                    if str(e.get("justification") or "").startswith("enc:v1:")
                    or str(e.get("query") or "").startswith("enc:v1:"))

    verify_result = verify_chain(events) if events else {"ok": False, "count": 0}

    # Output path
    short = session_id[:12]
    filename = f"immutrace_audit_{short}.pdf"
    out_path = config.EXPORT_DIR / filename

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        topMargin=1.6 * cm, bottomMargin=1.6 * cm,
        leftMargin=1.6 * cm, rightMargin=1.6 * cm,
        title=f"IMMUTRACE Audit Report — {short}",
        author="IMMUTRACE",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="H1", parent=styles["Heading1"],
        textColor=colors.HexColor("#0a2540"), fontSize=18, spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="H2", parent=styles["Heading2"],
        textColor=colors.HexColor("#0a2540"), fontSize=12, spaceBefore=10, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="Mono", parent=styles["BodyText"],
        fontName="Courier", fontSize=7, leading=9,
        textColor=colors.HexColor("#222"),
    ))
    styles.add(ParagraphStyle(
        name="MonoSmall", parent=styles["BodyText"],
        fontName="Courier", fontSize=6, leading=8,
        textColor=colors.HexColor("#444"),
    ))
    styles.add(ParagraphStyle(
        name="Hash", parent=styles["BodyText"],
        fontName="Courier", fontSize=6, leading=8,
        textColor=colors.HexColor("#666"),
    ))

    story = []

    # ── Header ──
    story.append(Paragraph("IMMUTRACE — Audit Trail Report", styles["H1"]))
    story.append(Paragraph(
        f"Cryptographic chain-of-custody for investigation session "
        f"<b>{session_id}</b>",
        styles["BodyText"],
    ))
    story.append(Spacer(1, 6))

    # ── §1 Investigator block ──
    story.append(Paragraph("1. Investigator &amp; justification", styles["H2"]))
    inv_table = Table(
        [
            ["Session ID",   session_id],
            ["Investigator", sess["actor"]],
            ["Activity",     sess["activity_type"]],
            ["Case ID",      sess["case_id"] or "—"],
            ["Justification", _mask_encrypted(sess["justification"])],
            ["Created",      sess["created_at"]],
            ["Expires",      sess["expires_at"]],
            ["Revoked",      "yes" if sess["revoked"] else "no"],
            ["Encryption",   (f"{enc_count} event field(s) encrypted at rest (AES-256-GCM); "
                              "shown as [ENCRYPTED], recoverable only with the master key "
                              "or erased per GDPR Art.17") if enc_count else "none"],
        ],
        colWidths=[3.5 * cm, 13 * cm],
    )
    inv_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#888")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#bbb")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0a2540")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(inv_table)
    story.append(Spacer(1, 8))

    # ── §2 Timeline ──
    story.append(Paragraph("2. Event timeline", styles["H2"]))
    story.append(Paragraph(
        f"<b>{len(events)} events</b> captured by the IMMUTRACE proxy. "
        f"Each row is hash-chained to the previous one (h<sub>n</sub> = SHA-256(h<sub>n-1</sub> || event)).",
        styles["BodyText"],
    ))
    story.append(Spacer(1, 4))

    if events:
        # Build a compact event table (first 60 events, then summary)
        rows = [["#", "Timestamp (UTC)", "Type", "Method", "Path", "Status", "Hash (8 chars)"]]
        max_rows = 80
        for i, e in enumerate(events[:max_rows], 1):
            ts = (e["ts"] or "")[:23]
            path = (e["path"] or "")[:48]
            rows.append([
                str(i), ts, (e["event_type"] or "")[:14],
                e["method"] or "", path,
                str(e["response_status"] or ""), (e["this_hash"] or "")[:8],
            ])
        if len(events) > max_rows:
            rows.append(["…", f"+ {len(events) - max_rows} more events", "", "", "", "", ""])
        evt_table = Table(rows, colWidths=[0.8 * cm, 3.3 * cm, 2.4 * cm, 1.2 * cm, 6 * cm, 1.3 * cm, 1.8 * cm])
        evt_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 6.5),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a2540")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
            ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor("#888")),
            ("INNERGRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#ccc")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 2.5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2.5),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(evt_table)
    else:
        story.append(Paragraph("<i>No events recorded for this session.</i>", styles["BodyText"]))

    story.append(Spacer(1, 10))

    # ── §3 Hash chain proof ──
    story.append(Paragraph("3. Hash-chain proof", styles["H2"]))
    if events:
        first_hash = events[0]["this_hash"]
        last_hash = events[-1]["this_hash"]
        prev_first = events[0]["prev_hash"]
        chain_status = "VERIFIED ✓" if verify_result["ok"] else f"TAMPERED at index {verify_result.get('broken_at')}"
        chain_color = colors.HexColor("#0a8a3f") if verify_result["ok"] else colors.HexColor("#c00")
        chain_tbl = Table([
            ["Chain status", chain_status],
            ["Event count", str(verify_result["count"])],
            ["Prev hash (before first event)", prev_first],
            ["First event hash", first_hash],
            ["Last event hash", last_hash],
        ], colWidths=[5 * cm, 11.5 * cm])
        chain_tbl.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Courier"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("TEXTCOLOR", (1, 0), (1, 0), chain_color),
            ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#888")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#bbb")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef")),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(chain_tbl)
    else:
        story.append(Paragraph("<i>No events → no chain to verify.</i>", styles["BodyText"]))

    story.append(Spacer(1, 10))

    # ── §4 On-chain anchors ──
    story.append(Paragraph("4. On-chain anchors (Polygon Amoy testnet / mock)", styles["H2"]))
    if anchors:
        rows = [["Anchor ID", "Chain", "Events", "Merkle root", "Tx hash", "Block"]]
        for a in anchors:
            rows.append([
                str(a["id"]), a["chain"], str(a["event_count"]),
                (a["merkle_root"] or "")[:16] + "…",
                (a["tx_hash"] or "")[:16] + "…",
                str(a["block_number"] or "—"),
            ])
        ach_tbl = Table(rows, colWidths=[1.5 * cm, 2.5 * cm, 1.5 * cm, 5 * cm, 5 * cm, 2 * cm])
        ach_tbl.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (3, 1), (4, -1), "Courier"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a2540")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
            ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor("#888")),
            ("INNERGRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#ccc")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(ach_tbl)
        story.append(Spacer(1, 4))
        for a in anchors:
            if a["chain"] == "polygon-amoy":
                link = f"https://amoy.polygonscan.com/tx/{a['tx_hash']}"
            else:
                link = f"(mock anchor — no on-chain tx, run with MOCK_ANCHOR=false for real submission)"
            story.append(Paragraph(
                f"Anchor #{a['id']} → <font face='Courier' size='6'>{link}</font>",
                styles["BodyText"],
            ))
    else:
        story.append(Paragraph(
            "<i>No on-chain anchor yet — events still pending in the local chain. "
            "Run POST /_immutrace/audit/anchor-now to force a batch.</i>",
            styles["BodyText"],
        ))

    # ── §5 QR verification ──
    story.append(Spacer(1, 12))
    story.append(Paragraph("5. Verification", styles["H2"]))
    verify_url = f"http://{config.PROXY_HOST}:{config.PROXY_PORT}/_immutrace/audit/verify/{session_id}"
    qr_buf = _qr_png(verify_url)
    qr_img = Image(qr_buf, width=3 * cm, height=3 * cm)
    note = Paragraph(
        "Scan or open the URL below to verify the integrity of this chain. "
        "The verifier recomputes every SHA-256 link end-to-end.<br/>"
        f"<font face='Courier' size='7'>{verify_url}</font>",
        styles["BodyText"],
    )
    verify_table = Table([[qr_img, note]], colWidths=[3.5 * cm, 13 * cm])
    verify_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(verify_table)

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        f"<i>Generated by IMMUTRACE Audit SDK v0.1 — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC</i>",
        styles["MonoSmall"],
    ))

    doc.build(story)

    # Compute PDF SHA-256 and rename to include hash
    pdf_bytes = out_path.read_bytes()
    pdf_sha = hashlib.sha256(pdf_bytes).hexdigest()
    final_name = f"immutrace_audit_{short}_{pdf_sha[:12]}.pdf"
    final_path = config.EXPORT_DIR / final_name
    if final_path != out_path:
        out_path.replace(final_path)

    return {
        "path": final_path,
        "filename": final_name,
        "sha256": pdf_sha,
        "session_id": session_id,
    }
