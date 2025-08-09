# tetrity

- [tetrity](#tetrity)
  - [Installation](#installation)
    - [Running from source](#running-from-source)
  - [Usage](#usage)

Automatically organises your downloads folder by moving files into category folders based on their extensions. It runs entirely in your terminal, requires minimal dependencies (`watchdog` and optionally `PyYAML`), and supports JSON/YAML config files with ignore patterns, renaming, and duplicate detection.

It uses multithreading to speed up moving files during initial scans and while watching for new files. Metadata is stored in a JSON file to prevent reprocessing duplicates.

## Installation

> \[!NOTE]
> This script requires Python 3.6+ and `watchdog`. Optional: `PyYAML` for YAML config support.

### Running from source

* Make sure [Python](https://python.org) is installed and available as `python` or `python3` in your terminal.
* Clone this repository.
* Install dependencies via pip:

```bash
python -m pip install src/requirements.txt
```

(`pyyaml` is optional unless you want YAML config support.)

## Usage

Run the script with:

```bash
python src/main.py
```
* Use `-c` or `--config` to specify a JSON/YAML config file.
* Use `-s` or `--scan-only` to organise existing files and exit.
* Use `-w` or `--watch-folder` to override the default watch folder (default is `~/Downloads`).
* Use `-v` or `--verbose` for debug logging.

Example:

```bash
python src/main.py --config config.yaml
```
