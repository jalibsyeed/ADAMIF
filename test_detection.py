from src.ingestion.ingestion_pipeline import IngestionPipeline
from src.detection.ssh_detection import SSHDetectionEngine

pipeline = IngestionPipeline(
    log_file_path="data/test_auth.log",
    storage_path="data/raw_events.jsonl"
)

events = pipeline.run()

engine = SSHDetectionEngine()
attacks = engine.detect(events)

print("Detection complete.")
print("Number of attacks detected:", len(attacks))

for attack in attacks:
    print("\n--- Attack Detected ---")
    print("Type:", attack.attack_type)
    print("Severity:", attack.severity)
    print("Confidence:", attack.confidence)
    print("Start:", attack.start_time)
    print("End:", attack.end_time)
    print("Frequency:", attack.frequency)
    print("Related Events:", len(attack.related_event_ids))
