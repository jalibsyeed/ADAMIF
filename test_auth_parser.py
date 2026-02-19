from src.ingestion.auth_log_parser import AuthLogParser

parser = AuthLogParser()

test_lines = [
    # Case 1: Failed login
    "Feb 17 14:12:32 kali sshd[1234]: Failed password for testuser from 192.168.1.100 port 22 ssh2",

    # Case 2: Successful login
    "Feb 17 14:15:00 kali sshd[1234]: Accepted password for jalib from 192.168.1.50 port 2222 ssh2",

    # Case 3: Invalid user
    "Feb 17 14:16:00 kali sshd[1234]: Invalid user hacker from 10.0.0.5 port 3333",

    # Case 4: Non-SSH line
    "Feb 17 14:20:00 kali systemd[1]: Started Some Service"
]

for i, line in enumerate(test_lines, 1):
    print(f"\n--- Test Case {i} ---")
    event = parser.parse(line)

    if event:
        print("Parsed successfully")
        print("Event Type:", event.event_type)
        print("Username:", event.username)
        print("Source IP:", event.source_ip)
        print("Port:", event.port)
        print("Raw Message:", event.raw_message)
    else:
        print("Parser returned None")
