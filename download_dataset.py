"""Download the official UCI PhiUSIIL CSV into the project's data folder."""

import argparse
import csv
import os
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

from config import DATASET_PATH


DATASET_URL = "https://archive.ics.uci.edu/static/public/967/data.csv"
MAX_DATASET_BYTES = 150 * 1024 * 1024


def download_dataset(destination: str | Path = DATASET_PATH, force: bool = False) -> Path:
    target = Path(destination)
    if target.is_file() and target.stat().st_size > 0 and not force:
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    request = Request(DATASET_URL, headers={"User-Agent": "PhishGuard-Student-Project/1.0"})
    temporary_path: str | None = None
    try:
        with urlopen(request, timeout=45) as response:
            with tempfile.NamedTemporaryFile(
                prefix=".uci-dataset-",
                suffix=".csv",
                dir=target.parent,
                delete=False,
            ) as temporary:
                temporary_path = temporary.name
                size = 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_DATASET_BYTES:
                        raise ValueError("Dataset download exceeded the 150 MB safety limit.")
                    temporary.write(chunk)
        with open(temporary_path, "r", encoding="utf-8-sig", newline="") as dataset_file:
            columns = {column.strip().lower() for column in next(csv.reader(dataset_file), [])}
        if not {"url", "label"}.issubset(columns):
            raise ValueError("Downloaded file is missing the expected URL and label columns.")
        os.replace(temporary_path, target)
        temporary_path = None
        return target
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch the official UCI PhiUSIIL URL dataset.")
    parser.add_argument("--force", action="store_true", help="Replace an existing dataset file.")
    arguments = parser.parse_args()
    try:
        path = download_dataset(force=arguments.force)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Dataset ready: {path} ({path.stat().st_size:,} bytes)")
