import argparse
import contextlib
import fnmatch
import hashlib
import json
import logging
import shutil
import threading
import time
from concurrent.futures import as_completed, ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

with contextlib.suppress(
    ImportError
):  # If not using YAML, then if we dont have pyyaml tis fine
    import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Logger setup


logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "watch_folder": str(Path.home() / "Downloads"),
    "categories": {
        "Images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"],
        "Music": [".mp3", ".wav", ".flac", ".aac"],
        "Documents": [".pdf", ".docx", ".txt", ".xlsx", ".pptx"],
        "Videos": [".mp4", ".mkv", ".avi"],
        "Archives": [".zip", ".rar", ".tar", ".gz"],
    },
    "exclude_types": [".tmp", ".crdownload"],
    "ignore_patterns": [],  # e.g. ['*.part', 'temp_*']
    "metadata_file": ".downloadsorter_metadata.json",
    "rename_pattern": "{timestamp}_{original}",
    "timestamp_format": "%Y%m%d_%H%M%S",
    "scan_on_start": True,
}


class Config:
    def __init__(self, path=None):
        self.config = DEFAULT_CONFIG.copy()

        if path:
            self.load_config(path)

    def load_config(self, path):
        p = Path(path)

        if not p.exists():
            logger.error(f"Config file not found: {path}")

            exit()
        try:
            if p.suffix.lower() in [".yaml", ".yml"]:
                if yaml is None:
                    raise ImportError(
                        "PyYAML is not installed. Please install it to use YAML config."
                    )
                with open(p, "r") as f:
                    user_config = yaml.safe_load(f)
            else:
                with open(p, "r") as f:
                    user_config = json.load(f)
            self.merge_config(user_config)
            logger.info(f"Loaded config from {path}")
        except Exception as e:
            logger.error(f"Failed to load config file {path}: {e}")
            exit()

    def get(self, key, default_value=None):
        item = self.config.get(key)

        return (
            item if item is not None else default_value
        )  # If we have ret or else def it

    def merge_config(self, user_config):
        for key, val in user_config.items():
            if isinstance(val, dict) and key in self.config:
                self.config[key].update(val)
            else:
                self.config[key] = val

    def __getitem__(self, key):  # Attr modifiers da goat
        return self.config.get(key)


class DownloadSorter:
    def __init__(self, config: Config):
        self.watch_folder = Path(config["watch_folder"])
        self.categories = config["categories"]
        self.exclude_types = set(config["exclude_types"])
        self.metadata_path = self.watch_folder / config["metadata_file"]
        self.ignore_patterns = config.get("ignore_patterns", []) + [
            str(config["metadata_file"])
        ]  # Otherwise it tries to move the metadata file lol
        self.rename_pattern = config["rename_pattern"]
        self.timestamp_format = config["timestamp_format"]
        self.metadata = self.load_metadata()
        self.lock = threading.Lock()  # Lock for metadata and other shared state stuff

    def load_metadata(self):
        if self.metadata_path.exists():
            try:
                with open(self.metadata_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(
                    f"Metadata file corrupted or unreadable, starting fresh: {e}"
                )
        return {}

    def save_metadata(self):
        try:
            with self.lock:
                with open(self.metadata_path, "w") as f:
                    json.dump(self.metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")

    def hash_file(self, path: Path) -> str:
        hasher = hashlib.sha256()

        while True:
            try:
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        hasher.update(chunk)
                return hasher.hexdigest()
            except PermissionError:
                continue  # Probs in the middle of copying, so just keep tryin
            except Exception as e:
                logger.error(f"Failed to hash {path}: {e}")
                return ""

    def get_category(self, ext: str) -> str:
        ext = ext.lower()

        for category, extensions in self.categories.items():
            if ext in extensions:
                return category
        return "Others"

    def format_filename(self, path: Path) -> str:
        timestamp = datetime.fromtimestamp(path.stat().st_mtime).strftime(
            self.timestamp_format
        )

        return self.rename_pattern.format(timestamp=timestamp, original=path.name)

    def matches_ignore(self, path: Path) -> bool:
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path.name, pattern):
                logger.debug(f"Ignoring {path} due to pattern {pattern}")
                return True
        return False

    def move_file_threadsafe(self, path: Path):
        if path.suffix.lower() in self.exclude_types:
            logger.debug(f"Excluded file type: {path.name}")
            return
        elif self.matches_ignore(path):
            return
        file_hash = self.hash_file(path)

        if not file_hash:
            return
        with self.lock:
            if file_hash in self.metadata.values():
                logger.info(f"Duplicate found, deleting: {path.name}")

                try:
                    path.unlink()
                    logger.info(f"Deleted duplicate file {path}")
                except Exception as e:
                    logger.error(f"Failed to delete duplicate file {path}: {e}")
                return
        category = self.get_category(path.suffix)
        target_dir = self.watch_folder / category
        target_dir.mkdir(exist_ok=True)

        new_name = self.format_filename(path)
        dest = target_dir / new_name

        counter = 1
        stem, suffix = dest.stem, dest.suffix

        while dest.exists():
            dest = target_dir / f"{stem}_{counter}{suffix}"
            counter += 1
        try:
            shutil.move(str(path), dest)

            with self.lock:
                self.metadata[str(dest)] = file_hash
            logger.info(f"Moved '{path.name}' -> '{dest}'")
        except Exception as e:
            logger.error(f"Failed to move file {path} to {dest}: {e}")

    def scan_folder(self, max_workers=4):
        logger.info(f"Scanning folder {self.watch_folder} with {max_workers} threads")
        files = [p for p in self.watch_folder.iterdir() if p.is_file()]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.move_file_threadsafe, f) for f in files]
            for _ in as_completed(futures):
                pass
        self.save_metadata()

    def watch(self, max_workers=10):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            event_handler = DownloadEventHandler(self, executor)
            observer = Observer()
            observer.schedule(event_handler, str(self.watch_folder), recursive=False)
            observer.start()
            logger.info(f"Started watching {self.watch_folder}")

            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                observer.stop()
                logger.info("Stopping observer...")
            observer.join()
        self.save_metadata()


class DownloadEventHandler(FileSystemEventHandler):
    def __init__(self, sorter: DownloadSorter, executor: ThreadPoolExecutor):
        self.sorter = sorter
        self.executor = executor

    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)

        self.executor.submit(self.sorter.move_file_threadsafe, path)


def parse_args():
    parser = argparse.ArgumentParser(
        description="DownloadSorter: Organize your downloads automatically."
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        help="Path to JSON/YAML config file (overrides default settings).",
    )
    parser.add_argument(
        "-s",
        "--scan-only",
        action="store_true",
        help="Scan and organize existing files once and exit.",
    )
    parser.add_argument(
        "-w", "--watch-folder", type=str, help="Override watch folder location."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging."
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    config = Config(args.config)

    if args.watch_folder:
        config.config["watch_folder"] = args.watch_folder
    sorter = DownloadSorter(config)

    if config["scan_on_start"]:
        sorter.scan_folder()
    if args.scan_only:
        logger.info("Scan-only mode: exiting after scan.")
        return
    sorter.watch()


if __name__ == "__main__":
    main()
