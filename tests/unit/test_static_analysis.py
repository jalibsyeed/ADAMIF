import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.malware.static_analysis import StaticAnalysisEngine


engine = StaticAnalysisEngine()


def test_random_noise():
    result = engine.analyze("tests/samples/noise/random.bin")

    assert result.risk_level == "LOW"
    assert result.suspicion_score == 0
    assert result.heuristic_flags == []


def test_evil_script_detected():
    result = engine.analyze("tests/samples/scripts/evil.sh")

    assert result.risk_level in {"MODERATE", "HIGH", "CRITICAL"}
    assert "SUSPICIOUS_STRING_REFERENCE" in result.heuristic_flags


def test_downloader_detected():
    result = engine.analyze("tests/samples/scripts/downloader.sh")

    assert result.risk_level in {"MODERATE", "HIGH", "CRITICAL"}
    assert "EMBEDDED_URL" in result.heuristic_flags


def test_benign_binary_safe():
    result = engine.analyze("tests/samples/benign/ls")

    assert result.risk_level == "LOW"
