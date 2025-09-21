#!/usr/bin/env python3
# -*- coding: utf8 -*-

# pylint: disable=missing-docstring               # [C0111] docstrings are always outdated and wrong
# pylint: disable=invalid-name                    # [C0103] single letter var names, name too descriptive(!)

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from epprint import epprint


class ForceRequiredError(Exception):
    pass


class SelfSymlinkError(Exception):
    def __init__(
        self,
        target,
        link_name,
    ):
        self.target = target
        self.link_name = link_name


class UnableToSetImmutableError(Exception):
    pass


def path_is_file(path: Path):
    # is_file returns False for symlinks to files
    # path_is_file will return True for symlink to existing file
    return path.exists() and stat.S_ISREG(os.lstat(path).st_mode)


def path_is_dir(path: Path):
    # is_dir returns False for symlinks to dirs
    # path_is_dir will return True for symlink to existing dir
    return path.exists() and stat.S_ISDIR(os.lstat(path).st_mode)


def path_is_symlink(path: Path):
    return stat.S_ISLNK(os.lstat(path).st_mode)


def path_is_dir_or_symlink_to_dir(path: Path):
    return path.is_dir() or (
        path.is_symlink() and Path(os.path.realpath(path)).is_dir()
    )


def path_is_file_or_symlink_to_file(path: Path):
    return path.is_file() or (
        path.is_symlink() and Path(os.path.realpath(path)).is_file()
    )


def chdir_or_exit(path: Path):
    try:
        os.chdir(path)
    except Exception as e:
        epprint("Got Exception: %s", e)
        epprint("Unable to chdir to: %s Exiting.", path)
        sys.exit(1)


def mkdir_or_exit(
    folder: Path,
    confirm: bool = False,
    mode: int = 0o755,
):
    assert isinstance(folder, Path)
    if folder.exists():
        if not folder.is_dir():
            raise ValueError(f"{folder} exists but is not a dir")
        return

    if confirm:
        input(f"press enter to os.mkdir({folder})")

    try:
        os.mkdir(folder, mode=mode)
    except Exception as e:
        epprint("Got Exception: %s", e)
        epprint("Unable to mkdir: %s Exiting.", folder)
        sys.exit(1)


def symlink(
    *,
    target: Path,
    link_name: Path,
    confirm: bool = False,
):

    if confirm:
        input(f"press enter to os.symlink({target}, {link_name})")

    if link_name.resolve() == target.resolve():
        raise SelfSymlinkError(target, link_name)

    try:
        os.symlink(target, link_name)
    except Exception as e:
        epprint(
            f"error symlinking:\ntarget:    {target}\nlink_name: {link_name}\nerror: {e}"
        )
        sys.exit(1)


def symlink_final_resolved_path(path: Path) -> Path:
    if os.path.islink(path):
        _path = Path(os.path.realpath(path))
    else:
        _path = path
    return _path


def get_abs_path_of_first_symlink_target(path):
    link_target = os.readlink(path)
    # assert link_target
    link_dir = os.path.dirname(path)
    link_first_target_abs = os.path.join(link_dir, link_target)
    # ceprint(link_first_target_abs)
    link_first_target_abs_normpath = os.path.normpath(link_first_target_abs)
    # ceprint(link_first_target_abs_normpath)
    link_first_target_abs_normpath_abspath = os.path.abspath(
        link_first_target_abs_normpath
    )
    return link_first_target_abs_normpath_abspath


def get_symlink_target_next(path):
    assert os.path.islink(path)
    target = os.readlink(path)
    return target


def get_symlink_target_final(path):  # broken for bytes
    if os.path.islink(path):
        target = os.readlink(path)
        target_joined = os.path.join(os.path.dirname(path), target)
        target_file = readlinkf(target_joined).decode("UTF-8")
    else:
        target_file = readlinkf(path).decode("UTF-8")
    return target_file


def readlinkf(path):  # portable replacement for `readlink -f`
    # Use pathlib to resolve as much as possible without requiring the target to exist.
    p = Path(path)
    resolved = p.resolve(strict=False)
    # Maintain bytes return type for backward compatibility with callers that decode.
    return os.fsencode(str(resolved))


def is_broken_symlink(path):
    if os.path.islink(path):  # path is a symlink
        return not os.path.exists(path)  # returns False for broken symlinks
    return False  # path isnt a symlink


def is_unbroken_symlink(path):
    if os.path.islink(path):  # path is a symlink
        return os.path.exists(path)  # returns False for broken symlinks
    return False  # path isnt a symlink


def calculate_relative_symlink_dest(
    *,
    target: Path,
    link_name: Path,
) -> str:
    # Standardize on Path inputs
    target = Path(target)
    link_name = Path(link_name)
    # Require target to exist to preserve previous behavior (no broken symlinks)
    target_resolved = target.resolve(strict=True)
    link_dir = link_name.parent.resolve(strict=True)
    # Relative path from link's directory to target
    rel = os.path.relpath(target_resolved, start=link_dir)
    return rel


def create_relative_symlink(
    *,
    target: Path,
    link_name: Path,
):
    # Compute a stable relative target and create the link atomically when possible.
    rel = calculate_relative_symlink_dest(target=target, link_name=link_name)
    link_path = Path(link_name)
    link_path.unlink(missing_ok=True)
    link_path.symlink_to(rel)


def symlink_destination(link):  # broken for multi level symlinks
    return os.path.realpath(link)


def make_file_immutable(path: Path):
    # Do not escalate privileges here; caller should have permission.
    result = subprocess.run(
        ["/usr/bin/chattr", "+i", path.as_posix()],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise UnableToSetImmutableError(result.stderr or result.stdout)
    check = subprocess.run(
        ["/usr/bin/lsattr", "--", path.as_posix()],
        capture_output=True,
        text=True,
    )
    # Parse flags from the first whitespace-separated field
    flags = check.stdout.split()[0] if check.stdout else ""
    if "i" not in flags:
        epprint(f"make_file_immutable({path.as_posix()}) failed")
        raise UnableToSetImmutableError(check.stdout or check.stderr)


def delete_file_and_recreate_empty_immutable(path: str | Path):
    path = Path(path)
    try:
        make_file_not_immutable(path)
    except FileNotFoundError:
        pass
    else:
        path.unlink()
    path.touch()
    make_file_immutable(path=path)


def make_file_not_immutable(path: Path):
    if path.exists():
        # Do not use sudo; assume caller has rights.
        result = subprocess.run(
            ["/usr/bin/chattr", "-i", path.as_posix()],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise UnableToSetImmutableError(result.stderr or result.stdout)
        check = subprocess.run(
            ["/usr/bin/lsattr", "--", path.as_posix()],
            capture_output=True,
            text=True,
        )
        flags = check.stdout.split()[0] if check.stdout else ""
        if "i" in flags:
            epprint(f"make_file_not_immutable({path.as_posix()}) failed")
            raise UnableToSetImmutableError(check.stdout or check.stderr)
    else:
        raise FileNotFoundError


def get_disk_free_bytes(path: Path) -> int:
    s = os.statvfs(path.as_posix())
    return s.f_frsize * s.f_bavail


# https://stackoverflow.com/questions/1430446/create-a-temporary-fifo-named-pipe-in-python
@contextmanager
def temp_fifo():
    """Context Manager for creating named pipes with temporary names."""
    tmpdir = tempfile.mkdtemp()
    filename = os.path.join(tmpdir, "fifo")  # Temporary filename
    os.mkfifo(filename)  # Create FIFO
    try:
        yield filename
    finally:
        os.unlink(filename)  # Remove file
        os.rmdir(tmpdir)  # Remove directory


def get_free_space_at_path(path: Path):
    assert isinstance(path, Path)
    st = os.statvfs(path)
    # Free bytes available to unprivileged processes
    free_bytes = st.f_bavail * st.f_frsize
    assert isinstance(free_bytes, int)
    return free_bytes


def get_path_with_most_free_space(
    pathlist: list[Path],
):
    assert isinstance(pathlist, (list, tuple))
    largest: None | tuple[int, Path] = None
    for path in pathlist:
        free_bytes: int = get_free_space_at_path(
            path=path,
        )
        if largest is None:
            largest = (free_bytes, path)
            continue
        if free_bytes > largest[0]:
            largest = (free_bytes, path)

    if largest:
        return Path(largest[1])
    raise ValueError


def longest_prefix(iter0, iter1):
    """
    Returns the longest common prefix of the given two iterables.
    """
    _longest_prefix = []
    for elmt0, elmt1 in zip(iter0, iter1):
        if elmt0 != elmt1:
            break
        _longest_prefix.append(elmt0)
    return _longest_prefix


def __is_disk_device(d: str):
    # quick and dirty
    assert d.count("/") < 2
    d = d.replace("/dev/", "")
    assert "/" not in d
    assert d.isalnum()
    assert d.lower() == d  # disallow uppercase
    disknames = [
        "mmcblk0",
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
    ]
    return d in disknames


def get_avail_for_user(path: Path) -> int:
    assert isinstance(path, Path)
    # The number of free blocks available to a non-super user:
    DISKFREE = shutil.disk_usage(path.as_posix())
    # t = os.statvfs(path.as_posix())
    # return t.f_bavail * t.f_bsize
    return DISKFREE.free


def get_pretty_bytes_string(byte_count: int) -> str:
    assert isinstance(byte_count, int)
    suffixes = {
        0: "B",
        1: "KiB",
        2: "MiB",
        3: "GiB",
        4: "TiB",
        5: "PiB",
        6: "EiB",
        7: "ZiB",
        8: "YiB",
    }

    i = 0
    while byte_count > 1024**i and i in suffixes:
        i += 1
    i -= 1
    assert i in suffixes
    rv = ("%.3f" % (byte_count / (1024**i))) + " " + suffixes[i]
    return rv


def touch_file_notify(
    fpath,
    args="r",
    timeout=1,
):
    assert args in {
        "r",
        "w",
        "x",
    }  # r: read, w: write, x: exclusive
    assert os.path.isabs(fpath)

    while True:
        flags = os.O_CREAT

        if args == "r":
            fflags = 0
        elif args == "w":
            fflags = os.O_TRUNC
        elif args == "x":
            fflags = os.O_EXCL
        else:
            assert False

        try:
            fd = os.open(fpath, fflags | flags)
            break
        except Exception as e:
            if e.errno == 17:
                # file exists
                if args == "x":
                    time.sleep(timeout)
                else:
                    break

    os.close(fd)


def dir_walk(
    path: Path,
    function,
    remove_root: bool,
    include_root: bool,
):
    assert isinstance(path, Path)
    if not path.exists():
        return

    assert path.is_dir()

    if include_root:
        function(path)
    files = None
    for root, dirs, files in os.walk(
        path,
        topdown=False,
    ):
        _root = Path(root)
        for name in files:
            file = _root / Path(name)
            function(file)
        for name in dirs:
            dir_ = _root / Path(name)
            function(dir_)

    if files is not None:
        if len(files) == 0 and remove_root:
            os.rmdir(path)


def really_is_dir(path: Path):
    if path.is_symlink():
        return False
    if (
        path.is_dir()
    ):  # is_dir() answers False for broken symlinks, and crashes with an OSError on self-symlinks
        return True
    return False
