from src.ingestion.ingestion_pipeline import IngestionPipeline
from src.detection.ssh_detection import SSHDetectionEngine
from src.detection.auth_behavior_detection import AuthBehaviorDetectionEngine

# Run ingestion
pipeline = IngestionPipeline(
    log_file_path="data/test_auth.log",
    storage_path="data/raw_events.jsonl"
)

events = pipeline.run()

# Run detection engines
ssh_engine = SSHDetectionEngine()
auth_engine = AuthBehaviorDetectionEngine()

ssh_attacks = ssh_engine.detect(events)
auth_attacks = auth_engine.detect(events)

print("===== SSH Detection =====")
print("Detected:", len(ssh_attacks))
for attack in ssh_attacks:
    print(attack.attack_type, attack.frequency)

print("\n===== Auth Behavior Detection =====")
print("Detected:", len(auth_attacks))
for attack in auth_attacks:
    print(attack.attack_type, attack.frequency)
