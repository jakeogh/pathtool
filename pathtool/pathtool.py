#!/usr/bin/env python3
"""Path manipulation utilities with modern Python features and comprehensive error handling."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from typing import Union

logger = logging.getLogger(__name__)


class ForceRequiredError(Exception):
    """Raised when a force flag is required for a dangerous operation."""

    pass


class SelfSymlinkError(Exception):
    """Raised when attempting to create a symlink that would point to itself."""

    def __init__(
        self,
        target: Path,
        link_name: Path,
    ) -> None:
        self.target = target
        self.link_name = link_name
        super().__init__(
            f"Cannot create self-referencing symlink: {link_name} -> {target}"
        )


class UnableToSetImmutableError(Exception):
    """Raised when unable to set or unset the immutable flag on a file."""

    pass


def path_is_file(path: Path) -> bool:
    """Return True if path exists and is a regular file (including symlinks to files).

    Args:
        path: Path to check

    Returns:
        True if path exists and is a file or symlink to a file
    """
    return path.exists() and path.is_file()


def path_is_dir(path: Path) -> bool:
    """Return True if path exists and is a directory (including symlinks to dirs).

    Args:
        path: Path to check

    Returns:
        True if path exists and is a directory or symlink to a directory
    """
    return path.exists() and path.is_dir()


def path_is_symlink(path: Path) -> bool:
    """Return True if path is a symbolic link.

    Args:
        path: Path to check

    Returns:
        True if path is a symbolic link, False otherwise
    """
    try:
        return path.is_symlink()
    except OSError:
        return False


def path_is_dir_or_symlink_to_dir(path: Path) -> bool:
    """Return True if path is a directory or symlink pointing to a directory.

    Args:
        path: Path to check

    Returns:
        True if path is a directory or symlink to an existing directory
    """
    return path.is_dir() or (path.is_symlink() and path.resolve().is_dir())


def path_is_file_or_symlink_to_file(path: Path) -> bool:
    """Return True if path is a file or symlink pointing to a file.

    Args:
        path: Path to check

    Returns:
        True if path is a file or symlink to an existing file
    """
    return path.is_file() or (path.is_symlink() and path.resolve().is_file())


def chdir_or_exit(path: Path) -> None:
    """Change directory or exit with error message.

    Args:
        path: Directory to change to
    """
    try:
        os.chdir(path)
    except OSError as e:
        logger.error(
            "Failed to change directory to %s: %s",
            path,
            e,
        )
        sys.exit(1)


def mkdir_or_exit(
    folder: Path,
    confirm: bool = False,
    mode: int = 0o755,
) -> None:
    """Create directory or exit with error message.

    Args:
        folder: Directory to create
        confirm: If True, prompt user before creating
        mode: File permissions for the directory

    Raises:
        ValueError: If folder exists but is not a directory
    """
    if folder.exists():
        if not folder.is_dir():
            raise ValueError(f"{folder} exists but is not a directory")
        return

    if confirm:
        input(f"Press enter to create directory: {folder}")

    try:
        folder.mkdir(mode=mode, parents=False)
    except OSError as e:
        logger.error(
            "Failed to create directory %s: %s",
            folder,
            e,
        )
        sys.exit(1)


def create_symlink(
    *,
    target: Path,
    link_name: Path,
    confirm: bool = False,
) -> None:
    """Create a symbolic link.

    Args:
        target: Path the symlink should point to
        link_name: Path where the symlink should be created
        confirm: If True, prompt user before creating

    Raises:
        SelfSymlinkError: If the symlink would point to itself
    """
    if confirm:
        input(f"Press enter to create symlink: {link_name} -> {target}")

    if link_name.resolve() == target.resolve():
        raise SelfSymlinkError(target, link_name)

    try:
        link_name.symlink_to(target)
    except OSError as e:
        logger.error(
            "Failed to create symlink %s -> %s: %s",
            link_name,
            target,
            e,
        )
        sys.exit(1)


def resolve_symlink_final(path: Path) -> Path:
    """Get the final resolved path, following all symlinks.

    Args:
        path: Path to resolve

    Returns:
        Final resolved path
    """
    return path.resolve()


def get_symlink_target(path: Path) -> str:
    """Get the immediate target of a symlink.

    Args:
        path: Symlink path

    Returns:
        Target path as string

    Raises:
        ValueError: If path is not a symlink
    """
    if not path.is_symlink():
        raise ValueError(f"{path} is not a symlink")

    return os.readlink(path)


def is_broken_symlink(path: Path) -> bool:
    """Check if path is a broken symbolic link.

    Args:
        path: Path to check

    Returns:
        True if path is a symlink pointing to a non-existent target
    """
    return path.is_symlink() and not path.exists()


def is_valid_symlink(path: Path) -> bool:
    """Check if path is a valid (unbroken) symbolic link.

    Args:
        path: Path to check

    Returns:
        True if path is a symlink pointing to an existing target
    """
    return path.is_symlink() and path.exists()


def calculate_relative_symlink_target(
    *,
    target: Path,
    link_name: Path,
) -> str:
    """Calculate relative path for creating a symlink.

    Args:
        target: Absolute path to the target
        link_name: Absolute path where the symlink will be created

    Returns:
        Relative path string from link location to target

    Raises:
        FileNotFoundError: If target doesn't exist
    """
    target = Path(target)
    link_name = Path(link_name)

    # Require target to exist
    target_resolved = target.resolve(strict=True)
    link_dir = link_name.parent.resolve(strict=True)

    return os.path.relpath(target_resolved, start=link_dir)


def create_relative_symlink(
    *,
    target: Path,
    link_name: Path,
) -> None:
    """Create a relative symbolic link.

    Args:
        target: Path the symlink should point to
        link_name: Path where the symlink should be created
    """
    relative_target = calculate_relative_symlink_target(
        target=target, link_name=link_name
    )
    link_name.unlink(missing_ok=True)
    link_name.symlink_to(relative_target)


def _is_file_immutable(path: Path) -> bool:
    """Check if file has the immutable flag set.

    Args:
        path: File path to check

    Returns:
        True if file has immutable flag set
    """
    if not shutil.which("lsattr"):
        return False

    try:
        result = subprocess.run(
            ["lsattr", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        flags = result.stdout.split()[0] if result.stdout else ""
        return "i" in flags
    except subprocess.CalledProcessError:
        return False


def make_file_immutable(path: Path) -> None:
    """Make file immutable using chattr +i.

    Args:
        path: File to make immutable

    Raises:
        UnableToSetImmutableError: If operation fails
    """
    if not shutil.which("chattr"):
        raise UnableToSetImmutableError("chattr command not found")

    try:
        subprocess.run(
            ["chattr", "+i", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise UnableToSetImmutableError(f"Failed to set immutable: {e.stderr}")

    # Verify the operation succeeded
    if not _is_file_immutable(path):
        raise UnableToSetImmutableError("File immutable flag not set after operation")


def make_file_not_immutable(path: Path) -> None:
    """Remove immutable flag from file using chattr -i.

    Args:
        path: File to make mutable

    Raises:
        FileNotFoundError: If file doesn't exist
        UnableToSetImmutableError: If operation fails
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not shutil.which("chattr"):
        raise UnableToSetImmutableError("chattr command not found")

    try:
        subprocess.run(
            ["chattr", "-i", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise UnableToSetImmutableError(f"Failed to remove immutable: {e.stderr}")

    # Verify the operation succeeded
    if _is_file_immutable(path):
        raise UnableToSetImmutableError("File immutable flag still set after operation")


def delete_file_and_recreate_empty_immutable(path: Union[str, Path]) -> None:
    """Delete file and recreate as empty immutable file.

    Args:
        path: File path to recreate
    """
    path = Path(path)

    try:
        make_file_not_immutable(path)
        path.unlink()
    except FileNotFoundError:
        pass

    path.touch()
    make_file_immutable(path)


def get_free_space(path: Path) -> int:
    """Get available free space at the given path in bytes.

    Args:
        path: Path to check free space for

    Returns:
        Available free space in bytes
    """
    path = Path(path)
    stat_result = os.statvfs(path)
    return stat_result.f_bavail * stat_result.f_frsize


@contextmanager
def temp_fifo() -> Iterator[str]:
    """Context manager for creating temporary named pipes.

    Yields:
        Path to the temporary FIFO
    """
    tmpdir = tempfile.mkdtemp()
    filename = os.path.join(tmpdir, "fifo")

    try:
        os.mkfifo(filename)
        yield filename
    finally:
        try:
            os.unlink(filename)
        except OSError:
            pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


def get_path_with_most_free_space(pathlist: list[Path]) -> Path:
    """Return the path with the most available free space.

    Args:
        pathlist: List of Path objects to check

    Returns:
        Path object with the most free space

    Raises:
        ValueError: If pathlist is empty or no valid paths found
    """
    if not pathlist:
        raise ValueError("pathlist cannot be empty")

    max_free_space = -1
    best_path = None

    for path in pathlist:
        try:
            free_bytes = get_free_space(path)
            if free_bytes > max_free_space:
                max_free_space = free_bytes
                best_path = path
        except OSError as e:
            logger.warning(
                "Cannot access path %s: %s",
                path,
                e,
            )
            continue

    if best_path is None:
        raise ValueError("No accessible paths found")

    return best_path


def longest_common_prefix(iter1: list, iter2: list) -> list:
    """Return the longest common prefix of two iterables.

    Args:
        iter1: First iterable
        iter2: Second iterable

    Returns:
        List containing the longest common prefix elements
    """
    common_prefix = []
    for element1, element2 in zip(iter1, iter2):
        if element1 != element2:
            break
        common_prefix.append(element1)
    return common_prefix


def is_disk_device(device_name: str) -> bool:
    """Check if the given name represents a valid disk device.

    Args:
        device_name: Device name (e.g., 'sda', 'nvme0n1')

    Returns:
        True if device_name is a recognized disk device
    """
    # Remove leading /dev/ if present
    device_name = device_name.replace("/dev/", "")

    # Basic validation
    if (
        "/" in device_name
        or not device_name.isalnum()
        or device_name != device_name.lower()
    ):
        return False

    # Known disk device patterns
    recognized_devices = {
        "mmcblk0",
        "mmcblk1",
        "mmcblk2",
        "sda",
        "sdb",
        "sdc",
        "sdd",
        "sde",
        "sdf",
        "sdg",
        "sdh",
        "sdi",
        "nvme0n1",
        "nvme1n1",
        "nvme2n1",
        "nvme3n1",
    }

    return device_name in recognized_devices


def format_bytes(byte_count: int) -> str:
    """Format byte count as human-readable string with binary prefixes.

    Args:
        byte_count: Number of bytes

    Returns:
        Formatted string (e.g., "1.50 GiB")
    """
    if byte_count < 0:
        return f"-{format_bytes(-byte_count)}"

    suffixes = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"]

    if byte_count == 0:
        return "0 B"

    for i, suffix in enumerate(suffixes):
        if byte_count < 1024 ** (i + 1) or i == len(suffixes) - 1:
            if i == 0:
                return f"{byte_count} {suffix}"
            else:
                value = byte_count / (1024**i)
                return f"{value:.2f} {suffix}"

    # This should never be reached
    return f"{byte_count} B"


def create_file_with_exclusive_access(
    file_path: Path,
    mode: str = "r",
    timeout: float = 1.0,
) -> None:
    """Create file with specified access mode, waiting if necessary.

    Args:
        file_path: Absolute path to the file
        mode: Access mode - 'r' (read), 'w' (write), 'x' (exclusive)
        timeout: Time to wait between attempts for exclusive access

    Raises:
        ValueError: If mode is invalid or path is not absolute
    """
    if mode not in {"r", "w", "x"}:
        raise ValueError(f"Invalid mode: {mode}. Must be 'r', 'w', or 'x'")

    if not file_path.is_absolute():
        raise ValueError(f"Path must be absolute: {file_path}")

    flags = os.O_CREAT

    if mode == "r":
        file_flags = 0
    elif mode == "w":
        file_flags = os.O_TRUNC
    elif mode == "x":
        file_flags = os.O_EXCL

    while True:
        try:
            fd = os.open(file_path, file_flags | flags)
            os.close(fd)
            break
        except FileExistsError:
            if mode == "x":
                time.sleep(timeout)
            else:
                break
        except OSError as e:
            logger.error(
                "Failed to create file %s: %s",
                file_path,
                e,
            )
            raise


def walk_directory(
    path: Path,
    callback: callable,
    remove_empty_root: bool = False,
    include_root: bool = False,
) -> None:
    """Walk directory tree and apply callback to each file/directory.

    Args:
        path: Root directory to walk
        callback: Function to call for each path
        remove_empty_root: Remove root directory if empty after processing
        include_root: Include root directory in processing
    """
    if not path.exists() or not path.is_dir():
        return

    if include_root:
        callback(path)

    processed_files = False

    for root, dirs, files in os.walk(path, topdown=False):
        root_path = Path(root)

        # Process files first
        for filename in files:
            file_path = root_path / filename
            callback(file_path)
            processed_files = True

        # Then process directories
        for dirname in dirs:
            dir_path = root_path / dirname
            callback(dir_path)

    # Remove root if requested and it's empty
    if remove_empty_root and not processed_files:
        try:
            path.rmdir()
        except OSError:
            pass  # Directory not empty or other error


def is_real_directory(path: Path) -> bool:
    """Check if path is a real directory (not a symlink).

    Args:
        path: Path to check

    Returns:
        True if path is a directory and not a symlink
    """
    return path.is_dir() and not path.is_symlink()
