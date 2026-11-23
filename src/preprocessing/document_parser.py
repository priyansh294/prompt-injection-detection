"""
Document Ingestion and Chunk-Level Security Analyzer
Implements FR-01, FR-02, FR-11 per SRS v1.0:
- Supports PDF extraction (via PyMuPDF) and plain text (.txt).
- Sentence-aware document chunking with configurable overlap.
- Chunk-level prompt-injection scanning and quarantine evaluation.
- Document-level security risk aggregation and reporting.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import io
import re

try:
    import pymupdf as fitz  # PyMuPDF
except ImportError:
    try:
        import fitz
    except ImportError:
        fitz = None

from src.engine.risk_engine import RiskAssessmentEngine, RiskAssessmentReport


@dataclass
class ScannedChunk:
    chunk_id: int
    text: str
    page_number: int
    risk_report: RiskAssessmentReport
    is_quarantined: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "text": self.text,
            "page_number": self.page_number,
            "classification": self.risk_report.classification,
            "threat_level": self.risk_report.threat_level,
            "risk_score": self.risk_report.risk_score,
            "action": self.risk_report.action,
            "is_quarantined": self.is_quarantined,
            "explanation": self.risk_report.explanation,
            "scores_breakdown": self.risk_report.scores_breakdown,
            "detection_details": self.risk_report.detection_details,
        }


@dataclass
class DocumentScanSummary:
    document_name: str
    total_characters: int
    total_chunks: int
    safe_chunks_count: int
    suspicious_chunks_count: int
    malicious_chunks_count: int
    quarantined_chunks_count: int
    overall_risk_score: float
    overall_threat_level: str
    overall_action: str
    chunks: List[ScannedChunk] = field(default_factory=list)
    document_summary_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_name": self.document_name,
            "total_characters": self.total_characters,
            "total_chunks": self.total_chunks,
            "safe_chunks_count": self.safe_chunks_count,
            "suspicious_chunks_count": self.suspicious_chunks_count,
            "malicious_chunks_count": self.malicious_chunks_count,
            "quarantined_chunks_count": self.quarantined_chunks_count,
            "overall_risk_score": self.overall_risk_score,
            "overall_threat_level": self.overall_threat_level,
            "overall_action": self.overall_action,
            "document_summary_text": self.document_summary_text,
            "chunks": [c.to_dict() for c in self.chunks]
        }


class DocumentScanner:
    def __init__(
        self,
        risk_engine: Optional[RiskAssessmentEngine] = None,
        chunk_size: int = 400,
        chunk_overlap: int = 50
    ):
        self.risk_engine = risk_engine or RiskAssessmentEngine()
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def extract_text_from_file(self, file_source: Union[str, Path, bytes, io.BytesIO], filename: str = "document") -> List[Dict[str, Any]]:
        """
        Extracts pages and text from PDF or TXT input.
        Returns a list of dicts: [{"page": 1, "text": "..."}]
        """
        lower_name = filename.lower()
        pages = []

        if lower_name.endswith(".pdf"):
            if fitz is None:
                raise RuntimeError("PyMuPDF (fitz) is not installed. PDF extraction unavailable.")
            
            if isinstance(file_source, (str, Path)):
                doc = fitz.open(str(file_source))
            elif isinstance(file_source, bytes):
                doc = fitz.open(stream=file_source, filetype="pdf")
            else:
                doc = fitz.open(stream=file_source.read(), filetype="pdf")

            for page_idx in range(len(doc)):
                page = doc.load_page(page_idx)
                text = page.get_text()
                if text.strip():
                    pages.append({"page": page_idx + 1, "text": text})
            doc.close()
        else:
            # Handle plain text / markdown / other text types
            if isinstance(file_source, (str, Path)):
                with open(file_source, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            elif isinstance(file_source, bytes):
                content = file_source.decode("utf-8", errors="replace")
            else:
                content = file_source.read().decode("utf-8", errors="replace")

            pages.append({"page": 1, "text": content})

        return pages

    def chunk_text(self, pages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Splits extracted pages into manageable chunks while preserving page provenance.
        """
        chunks = []
        chunk_id = 1

        for page_data in pages:
            page_num = page_data["page"]
            text = page_data["text"]

            # Sentence-aware chunking
            sentences = re.split(r'(?<=[.!?\n])\s+', text)
            current_chunk_words: List[str] = []
            current_len = 0

            for sent in sentences:
                sent = sent.strip()
                if not sent:
                    continue
                words = sent.split()
                if current_len + len(words) > self.chunk_size and current_chunk_words:
                    chunk_str = " ".join(current_chunk_words)
                    chunks.append({
                        "chunk_id": chunk_id,
                        "page_number": page_num,
                        "text": chunk_str
                    })
                    chunk_id += 1
                    # Retain overlap words
                    overlap_words = current_chunk_words[-self.chunk_overlap:] if len(current_chunk_words) > self.chunk_overlap else []
                    current_chunk_words = overlap_words + words
                    current_len = len(current_chunk_words)
                else:
                    current_chunk_words.extend(words)
                    current_len += len(words)

            if current_chunk_words:
                chunk_str = " ".join(current_chunk_words)
                chunks.append({
                    "chunk_id": chunk_id,
                    "page_number": page_num,
                    "text": chunk_str
                })
                chunk_id += 1

        return chunks

    def scan_document(
        self,
        file_source: Union[str, Path, bytes, io.BytesIO],
        filename: str = "document.txt"
    ) -> DocumentScanSummary:
        """
        Extracts text, segments into chunks, analyzes each chunk via the risk engine,
        and aggregates document-level safety statistics.
        """
        pages = self.extract_text_from_file(file_source, filename)
        total_chars = sum(len(p["text"]) for p in pages)
        raw_chunks = self.chunk_text(pages)

        scanned_chunks: List[ScannedChunk] = []
        safe_count = 0
        suspicious_count = 0
        malicious_count = 0
        quarantined_count = 0

        for r_chunk in raw_chunks:
            # Scan chunk with risk engine
            report = self.risk_engine.analyze(
                text=r_chunk["text"],
                input_type="RetrievedChunk"
            )

            is_quarantined = (report.threat_level == "High" or report.action == "Block / Quarantine")
            if is_quarantined:
                quarantined_count += 1

            if report.classification == "Safe":
                safe_count += 1
            elif report.classification == "Suspicious":
                suspicious_count += 1
            else:
                malicious_count += 1

            scanned_chunks.append(ScannedChunk(
                chunk_id=r_chunk["chunk_id"],
                text=r_chunk["text"],
                page_number=r_chunk["page_number"],
                risk_report=report,
                is_quarantined=is_quarantined
            ))

        # Overall document risk calculation:
        # If any malicious chunk is present, overall document risk is driven by the maximum chunk risk
        if scanned_chunks:
            max_chunk_risk = max(c.risk_report.risk_score for c in scanned_chunks)
            avg_chunk_risk = sum(c.risk_report.risk_score for c in scanned_chunks) / len(scanned_chunks)
            # Weighted overall score heavily penalizing hostile payloads
            overall_risk = min(round((max_chunk_risk * 0.75) + (avg_chunk_risk * 0.25), 2), 100.0)
        else:
            overall_risk = 0.0

        low_max = self.risk_engine.thresholds.get("low_max", 29.0)
        med_max = self.risk_engine.thresholds.get("medium_max", 59.0)

        if overall_risk <= low_max:
            overall_threat = "Low"
            overall_action = "Allow"
        elif overall_risk <= med_max:
            overall_threat = "Medium"
            overall_action = "Review"
        else:
            overall_threat = "High"
            overall_action = "Block / Quarantine"

        summary_text = (
            f"Document '{filename}' scanned: {len(scanned_chunks)} chunk(s) evaluated. "
            f"{safe_count} Safe, {suspicious_count} Suspicious, {malicious_count} Malicious. "
            f"{quarantined_count} chunk(s) quarantined from RAG context."
        )

        return DocumentScanSummary(
            document_name=filename,
            total_characters=total_chars,
            total_chunks=len(scanned_chunks),
            safe_chunks_count=safe_count,
            suspicious_chunks_count=suspicious_count,
            malicious_chunks_count=malicious_count,
            quarantined_chunks_count=quarantined_count,
            overall_risk_score=overall_risk,
            overall_threat_level=overall_threat,
            overall_action=overall_action,
            chunks=scanned_chunks,
            document_summary_text=summary_text
        )
