import sys
from src.malware.static_analysis import StaticAnalysisEngine

if len(sys.argv) != 2:
    print("Usage: python test_static_analysis.py <file>")
    sys.exit(1)

file_path = sys.argv[1]

engine = StaticAnalysisEngine()
result = engine.analyze(file_path)

print("SHA256:", result.sha256)
print("File Type:", result.file_type)
print("Risk Level:", result.risk_level)
print("Score:", result.suspicion_score)
print("Flags:", result.heuristic_flags)
print("Capabilities:", result.capability_indicators)
print("Reasoning:", result.analysis_reasoning)
