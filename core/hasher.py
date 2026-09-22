"""SHA-256 Cryptographic Hash Engine for HashVault.

Provides chunk-based, memory-efficient SHA-256 fingerprinting for monitored files,
with built-in size safety thresholds and comprehensive OS error handling.
"""

import hashlib
import os
from pathlib import Path
from typing import Optional, Tuple

# Default maximum file size threshold for scanning (50 Megabytes)
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
# Standard chunk size for streaming file reads (64 Kilobytes)
CHUNK_SIZE = 65536  # 64 KB


def calculate_sha256(filepath: str, max_size_bytes: int = DEFAULT_MAX_FILE_SIZE) -> Tuple[Optional[str], Optional[str], int]:
    """Calculates the SHA-256 hexadecimal digest of a file in chunks.

    Args:
        filepath: Path to the target file.
        max_size_bytes: Maximum allowed file size in bytes before skipping.

    Returns:
        A tuple of:
            - sha256_hash: Hexadecimal digest string, or None if failed.
            - error_message: Error or skip explanation, or None if successful.
            - file_size: Size of the file in bytes, or 0 if unreadable.
    """
    path_obj = Path(filepath)

    if not path_obj.exists():
        return None, f"File not found: {filepath}", 0

    if not path_obj.is_file():
        return None, f"Path is not a regular file: {filepath}", 0

    try:
        file_stat = path_obj.stat()
        file_size = file_stat.st_size

        if file_size > max_size_bytes:
            return (
                None,
                f"File skipped because it exceeds the configured scan size limit ({file_size} > {max_size_bytes} bytes).",
                file_size,
            )

        sha256_hasher = hashlib.sha256()

        # Read in fixed chunks to prevent high memory usage
        with open(path_obj, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256_hasher.update(chunk)

        digest = sha256_hasher.hexdigest()
        return digest, None, file_size

    except PermissionError:
        return None, f"Permission denied accessing file: {filepath}", 0
    except FileNotFoundError:
        return None, f"File disappeared during read: {filepath}", 0
    except OSError as os_err:
        return None, f"OS error reading file: {str(os_err)}", 0
    except Exception as exc:
        return None, f"Unexpected error calculating hash: {str(exc)}", 0


def hash_string(data: str) -> str:
    """Calculates the SHA-256 hexadecimal digest of an in-memory UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
