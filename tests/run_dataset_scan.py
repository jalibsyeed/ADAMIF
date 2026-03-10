import sys
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.malware.static_analysis import StaticAnalysisEngine

engine = StaticAnalysisEngine()

sample_root = Path("tests/samples")

total_files = 0
benign_correct = 0
malicious_detected = 0
false_positives = 0
missed_malware = 0

for category in sample_root.iterdir():
    if not category.is_dir():
        continue

    print(f"\n=== CATEGORY: {category.name.upper()} ===")

    for file in category.iterdir():
        if not file.is_file():
            continue

        total_files += 1

        result = engine.analyze(str(file))

        print(f"\nFile: {file.name}")
        print(f"Type: {result.file_type}")
        print(f"Score: {result.suspicion_score}")
        print(f"Risk: {result.risk_level}")
        print(f"Flags: {result.heuristic_flags}")

        # ------------------------------------------------
        # Dataset validation logic
        # ------------------------------------------------

        if category.name == "benign":
            if result.risk_level == "LOW":
                benign_correct += 1
            else:
                false_positives += 1

        elif category.name == "scripts":
            if result.risk_level in {"MODERATE", "HIGH", "CRITICAL"}:
                malicious_detected += 1
            else:
                missed_malware += 1

# ------------------------------------------------
# Dataset Summary Report
# ------------------------------------------------

print("\n==============================")
print("DATASET SUMMARY REPORT")
print("==============================")

print(f"Total samples scanned: {total_files}")
print(f"Benign correctly classified: {benign_correct}")
print(f"Malicious samples detected: {malicious_detected}")
print(f"False positives: {false_positives}")
print(f"Missed malware: {missed_malware}")
