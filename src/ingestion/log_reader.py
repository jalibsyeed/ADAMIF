from pathlib import Path
from typing import Iterator


class LogReader:
    """
    LogReader reads raw log lines from a controlled file source.

    Responsibilities:
    - Open a deterministic file
    - Yield raw log lines
    - Perform no parsing
    - Perform no interpretation
    """

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)

        if not self.file_path.exists():
            raise FileNotFoundError(
                f"Log file does not exist: {self.file_path}"
            )

        if not self.file_path.is_file():
            raise ValueError(
                f"Provided path is not a file: {self.file_path}"
            )

    def read_lines(self) -> Iterator[str]:
        """
        Yields raw log lines exactly as stored,
        stripping only trailing newline characters.
        """
        with self.file_path.open("r", encoding="utf-8") as file:
            for line in file:
                yield line.rstrip("\n")
