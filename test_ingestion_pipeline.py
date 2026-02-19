from src.ingestion.ingestion_pipeline import IngestionPipeline

pipeline = IngestionPipeline(
    log_file_path="data/test_auth.log",
    storage_path="data/raw_events.jsonl"
)

events = pipeline.run()

print("Ingestion complete.")
print("Number of events parsed:", len(events))

print("\nParsed Events:")
for event in events:
    print(
        f"{event.timestamp} | "
        f"{event.event_type} | "
        f"user={event.username} | "
        f"ip={event.source_ip} | "
        f"port={event.port}"
    )

