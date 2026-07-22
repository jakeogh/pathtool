#!/usr/bin/env python3

import errno
import os
import stat
import tempfile
import time
from collections.abc import Callable
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import hs
from eprint import eprint


class ForceRequiredError(Exception):
    pass


class SelfSymlinkError(Exception):
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
    pass


def _kind_from_mode(mode: int) -> str:
    if stat.S_ISBLK(mode):
        return "block special"
    if stat.S_ISCHR(mode):
        return "character special"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISFIFO(mode):
        return "FIFO/pipe"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "regular file"
    if stat.S_ISSOCK(mode):
        return "socket"
    return f"unknown (mode=0o{mode:o})"


def wait_for_block_special_device_to_exist(
    *,
    device: Path,
    timeout: float = 5.0,
    poll: float = 0.10,
) -> bool:
    # does NOT follow symlinks: `device` must itself be a block device node
    assert isinstance(device, Path)
    assert timeout > 0
    assert poll > 0

    eprint(
        f"waiting for block special device (no symlinks): {device.as_posix()} "
        f"(timeout={timeout:.2f}s, poll={poll:.2f}s)"
    )

    if path_is_block_special(device, symlink_ok=False):
        eprint(f"device is ready: {device}")
        return True

    deadline = time.monotonic() + timeout
    last_mode: None | int = None

    while True:
        time.sleep(poll)

        try:
            st = os.lstat(device)
            last_mode = st.st_mode
        except (FileNotFoundError, NotADirectoryError):
            st = None

        if st is not None and stat.S_ISBLK(st.st_mode):
            eprint(f"device is ready: {device}")
            return True

        if time.monotonic() >= deadline:
            if st is None:
                raise TimeoutError(
                    f"timeout: device not found: {device} (no symlink following)"
                )
            raise TimeoutError(
                f"timeout: {device} exists but is {_kind_from_mode(last_mode)}; "
                f"required: block special (no symlink following)"
            )


def path_is_block_special(path: Path, symlink_ok: bool) -> bool:
    # symlink_ok follows symlinks and inspects the target
    assert isinstance(path, Path)
    try:
        st = os.stat(path, follow_symlinks=symlink_ok)
    except (FileNotFoundError, NotADirectoryError):
        return False
    return stat.S_ISBLK(st.st_mode)


def path_is_file(path: Path) -> bool:
    return path.is_file()


def path_is_dir(path: Path) -> bool:
    return path.is_dir()


def path_is_symlink(path: Path) -> bool:
    return path.is_symlink()


def path_is_dir_only(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink()


is_real_directory = path_is_dir_only


def path_is_dir_or_symlink_to_dir(path: Path) -> bool:
    return path.is_dir() or (path.is_symlink() and path.resolve().is_dir())


def path_is_file_or_symlink_to_file(path: Path) -> bool:
    return path.is_file() or (path.is_symlink() and path.resolve().is_file())


def file_exists_nonzero(path: Path) -> bool:
    assert isinstance(path, Path)
    return path.is_file() and path.stat().st_size > 0


def is_empty_file(path: Path) -> bool:
    assert isinstance(path, Path)
    return path.is_file() and path.stat().st_size == 0


def chdir_or_exit(path: Path) -> None:
    os.chdir(path)


def mkdir_or_exit(
    folder: Path,
    confirm: bool = False,
    mode: int = 0o755,
    parents: bool = True,
) -> None:
    if folder.exists():
        if not folder.is_dir():
            raise ValueError(f"{folder} exists but is not a directory")
        return

    if confirm:
        input(f"Press enter to create directory: {folder}")

    folder.mkdir(mode=mode, parents=parents)


def create_symlink(
    *,
    target: Path,
    link_name: Path,
    confirm: bool = False,
) -> None:
    if confirm:
        input(f"Press enter to create symlink: {link_name} -> {target}")

    if link_name.resolve() == target.resolve():
        raise SelfSymlinkError(target, link_name)

    link_name.symlink_to(target)


def resolve_symlink_final(path: Path) -> Path:
    return path.resolve()


def get_symlink_target(path: Path) -> str:
    if not path.is_symlink():
        raise ValueError(f"{path} is not a symlink")
    return os.readlink(path)


def is_broken_symlink(path: Path) -> bool:
    return path.is_symlink() and not path.exists()


def is_unbroken_symlink(path: Path) -> bool:
    return path.is_symlink() and path.exists()


is_valid_symlink = is_unbroken_symlink


def calculate_relative_symlink_target(
    *,
    target: Path,
    link_name: Path,
) -> str:
    target_resolved = Path(target).resolve(strict=True)
    link_dir = Path(link_name).parent.resolve(strict=True)
    return os.path.relpath(target_resolved, start=link_dir)


def create_relative_symlink(
    *,
    target: Path,
    link_name: Path,
) -> None:
    relative_target = calculate_relative_symlink_target(
        target=target, link_name=link_name
    )
    link_name.unlink(missing_ok=True)
    link_name.symlink_to(relative_target)


def _is_file_immutable(path: Path) -> bool:
    try:
        lsattr_output = str(hs.Command("lsattr")(path.as_posix()))
    except hs.ErrorReturnCode:
        return False
    flags = lsattr_output.split()[0] if lsattr_output else ""
    return "i" in flags


def make_file_immutable(path: Path) -> None:
    try:
        hs.Command("chattr")("+i", path.as_posix())
    except hs.ErrorReturnCode as e:
        raise UnableToSetImmutableError(f"Failed to set immutable: {e.stderr}") from e

    if not _is_file_immutable(path):
        raise UnableToSetImmutableError("File immutable flag not set after operation")


def make_file_not_immutable(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        hs.Command("chattr")("-i", path.as_posix())
    except hs.ErrorReturnCode as e:
        raise UnableToSetImmutableError(
            f"Failed to remove immutable: {e.stderr}"
        ) from e

    if _is_file_immutable(path):
        raise UnableToSetImmutableError("File immutable flag still set after operation")


def delete_file_and_recreate_empty_immutable(path: str | Path) -> None:
    path = Path(path)

    try:
        make_file_not_immutable(path)
        path.unlink()
    except FileNotFoundError:
        pass

    path.touch()
    make_file_immutable(path)


def get_free_space(path: Path) -> int:
    stat_result = os.statvfs(Path(path))
    return stat_result.f_bavail * stat_result.f_frsize


@contextmanager
def temp_fifo() -> Iterator[str]:
    tmpdir = tempfile.mkdtemp()
    filename = os.path.join(tmpdir, "fifo")

    try:
        os.mkfifo(filename)
        yield filename
    finally:
        os.unlink(filename)
        os.rmdir(tmpdir)


def get_path_with_most_free_space(pathlist: list[Path]) -> Path:
    if not pathlist:
        raise ValueError("pathlist cannot be empty")

    max_free_space = -1
    best_path = None

    for path in pathlist:
        free_bytes = get_free_space(path)
        if free_bytes > max_free_space:
            max_free_space = free_bytes
            best_path = path

    assert best_path is not None
    return best_path


def longest_common_prefix(iter1: list, iter2: list) -> list:
    common_prefix = []
    for element1, element2 in zip(iter1, iter2):
        if element1 != element2:
            break
        common_prefix.append(element1)
    return common_prefix


def is_disk_device(device_name: str) -> bool:
    device_name = device_name.replace("/dev/", "")

    if (
        "/" in device_name
        or not device_name.isalnum()
        or device_name != device_name.lower()
    ):
        return False

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
    if byte_count < 0:
        return f"-{format_bytes(-byte_count)}"

    if byte_count == 0:
        return "0 B"

    suffixes = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"]
    for i, suffix in enumerate(suffixes):
        if byte_count < 1024 ** (i + 1) or i == len(suffixes) - 1:
            if i == 0:
                return f"{byte_count} {suffix}"
            return f"{byte_count / (1024**i):.2f} {suffix}"
    raise AssertionError


def create_file_with_exclusive_access(
    file_path: Path,
    mode: str = "r",
    timeout: float = 1.0,
) -> None:
    # mode: r (create if missing), w (create/truncate), x (wait for exclusive create)
    if mode not in {"r", "w", "x"}:
        raise ValueError(f"Invalid mode: {mode}. Must be 'r', 'w', or 'x'")

    if not file_path.is_absolute():
        raise ValueError(f"Path must be absolute: {file_path}")

    file_flags = 0
    if mode == "w":
        file_flags = os.O_TRUNC
    elif mode == "x":
        file_flags = os.O_EXCL

    while True:
        try:
            fd = os.open(file_path, file_flags | os.O_CREAT)
            os.close(fd)
            break
        except FileExistsError:
            if mode == "x":
                time.sleep(timeout)
            else:
                break


def walk_directory(
    path: Path,
    callback: Callable,
    remove_empty_root: bool = False,
    include_root: bool = False,
) -> None:
    if not path.is_dir():
        return

    if include_root:
        callback(path)

    processed_files = False

    for root, dirs, files in os.walk(path, topdown=False):
        root_path = Path(root)
        for filename in files:
            callback(root_path / filename)
            processed_files = True
        for dirname in dirs:
            callback(root_path / dirname)

    if remove_empty_root and not processed_files:
        try:
            path.rmdir()
        except OSError as e:
            if e.errno != errno.ENOTEMPTY:
                raise


def wait_for_path_to_exist(
    path: Path,
    *,
    file_ok: bool,
    dir_ok: bool,
    timeout: None | int = None,
) -> None:
    start = time.time()

    while True:
        if path.exists():
            if (file_ok and path.is_file()) or (dir_ok and path.is_dir()):
                return

        if timeout is not None and (time.time() - start) >= timeout:
            raise TimeoutError(f"Path {path} did not appear within {timeout}s")

        time.sleep(0.1)


def remove_empty_folders(path: Path, *, recursive: bool = True) -> None:
    if not path.is_dir():
        return

    if recursive:
        for item in path.iterdir():
            if item.is_dir():
                remove_empty_folders(item, recursive=True)

    try:
        path.rmdir()
    except OSError as e:
        if e.errno != errno.ENOTEMPTY:
            raise
