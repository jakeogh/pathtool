#!/usr/bin/env python3
# -*- coding: utf8 -*-

# pylint: disable=C0111  # docstrings are always outdated and wrong
# pylint: disable=W0511  # todo is encouraged
# pylint: disable=C0301  # line too long
# pylint: disable=R0902  # too many instance attributes
# pylint: disable=C0302  # too many lines in module
# pylint: disable=C0103  # single letter var names, func name too descriptive
# pylint: disable=R0911  # too many return statements
# pylint: disable=R0912  # too many branches
# pylint: disable=R0915  # too many statements
# pylint: disable=R0913  # too many arguments
# pylint: disable=R1702  # too many nested blocks
# pylint: disable=R0914  # too many local variables
# pylint: disable=R0903  # too few public methods
# pylint: disable=E1101  # no member for base
# pylint: disable=W0201  # attribute defined outside __init__
# pylint: disable=R0916  # Too many boolean expressions in if statement

import errno
import fcntl
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from shutil import copyfileobj
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal

import click
#import magic  # sys-apps/file  #PIA
from asserttool import eprint
from asserttool import ic
from asserttool import nevd
from hashtool import sha3_256_hash_file
from retry_on_exception import retry_on_exception

signal(SIGPIPE, SIG_DFL)
from typing import ByteString
from typing import Generator
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence

from enumerate_input import enumerate_input
from psutil import disk_usage

signal(SIGPIPE, SIG_DFL)


def cli_path(path: str,
             verbose: bool,
             debug: bool,
             ):
    # problem, Path('~').expanduser() is ambigious
    # when there is a file named ~ in CWD
    # the obvious solution is to make the user specify
    # Path('./~') which .expanduser().... uug... .expanduser()
    # incorrectly resolves ./~ to /home/user.
    # sooo... is there no way to specify the ~ file without an absolute path?
    pass


def validate_slice(slice_syntax: str):
    assert isinstance(slice_syntax, str)
    for c in slice_syntax:
        if c not in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '[', ']', ':']:
            raise ValueError(slice_syntax)
    return slice_syntax


def path_is_dir(path):
    if os.path.isdir(path):  # could still be a symlink
        if os.path.islink(path):
            return False
        return True
    return False


def target_generator(target_list, min_free_space, verbose=True):
    if verbose:
        ic(min_free_space)
    for target in target_list:
        if verbose:
            ic(target)
        if path_exists(target):
            assert path_is_dir(target)
            free_space = disk_usage(target).free
            ic(free_space)
            if disk_usage(target).free >= min_free_space:
                yield target
            else:
                eprint("skipped:", target, "<", min_free_space)
    raise FileNotFoundError


def is_symlink(infile):
    if os.path.islink(infile):
        return True
    return False


def is_symlink_to_dir(link):
    if os.path.islink(link):
        return os.path.isdir(link)
    return False


def get_symlink_abs_target(link): # assumes link is unbroken
    target = os.readlink(link)
    target_joined = os.path.join(os.path.dirname(link), target)
    target_file = os.path.realpath(target_joined)
    return target_file


def gurantee_symlink(*,
                     target: Path,
                     link_name: Path,
                     relative: bool,
                     verbose: bool,
                     debug: bool,
                     ):
    # todo advisorylock
    if relative:
        raise NotImplementedError
    try:
        os.symlink(target, link_name)
    except FileExistsError as e:
        ic(e)
        assert Path(link_name).resolve().as_posix() == Path(target).as_posix()


def calculate_relative_symlink_dest(*,
                                    target: Path,
                                    link_name: Path,
                                    verbose: bool,
                                    debug: bool,
                                    ):

    # todo eval https://docs.python.org/3/library/os.path.html#os.path.commonpath
    if isinstance(target, str):
        target = bytes(target, encoding='UTF8')
    if isinstance(target, Path):
        target = os.fsencode(target)

    if isinstance(link_name, str):
        link_name = bytes(link_name, encoding='UTF8')
    if isinstance(link_name, Path):
        link_name = os.fsencode(link_name)

    # paths are bytes. this must work for all possible paths
    assert isinstance(target, bytes)
    assert isinstance(link_name, bytes)
    #ceprint("target:", target)

    assert not target.startswith(b'../')
    # got relative target, that's hard to deal with pass in a fully qualified path
    # if target is also an existing symlink, detect that and dont call realpath()
    # call something that gets the realpath but does not follow any links

    if is_unbroken_symlink(target):
        # the target is also a symlink, dont resolve it, just get it's abspath
        target_realpath = os.path.abspath(target)
        # still a problem, since this was not fully resolved, it may still have symlinks embedded in it
        # get the folder, resolve that since it's guranteed not to be a symlink
        target_realpath_folder = b'/'.join(target_realpath.split(b'/')[:-1])
        #ceprint("target_realpath_folder:", target_realpath_folder)
        target_realpath_file = target_realpath.split(b'/')[-1]
        #ceprint("target_realpath_file:", target_realpath_file)
        target_realpath_folder_realpath = os.path.realpath(target_realpath_folder)
        target_realpath = os.path.join(target_realpath_folder_realpath, target_realpath_file)
        # uug. ok now.

    elif path_exists(target):
        # target is prob a file or dir, but could still be a broken symlink
        target_realpath = os.path.realpath(target)

    elif is_broken_symlink(link_name):
        assert False

    else: # idk
        assert False

    if is_broken_symlink(link_name):
        link_name_realpath = os.path.realpath(link_name)
        #ceprint("link_name_realpath:", link_name_realpath)
    elif not path_exists(link_name):
        link_name_realpath = os.path.realpath(link_name)
        #ceprint("link_name_realpath:", link_name_realpath)

    # if its a unbroken symlink, and this is being used to see if its the shortest dest
    # os.path.realpath() cant be called, because it resolves the existing link to the target
    elif is_unbroken_symlink(link_name):
        link_name_realpath = os.path.abspath(link_name)
        #ceprint("link_name_realpath: (abspath)", link_name_realpath)
        # at this point, all is still not well.
        # link_name_realpath was actually constructed by abspath()
        # so if its really on a different filesystem, the link
        # might not reflect that.
        # the solution is to call realpath() on link_name_realpath_folder
        # since its not a symlink, this will work as expected
    else:
        assert False

    if not path_exists(target_realpath):
        ic(target_realpath, 'does not exist. Refusing to make broken symlink.')
        raise FileNotFoundError

    if is_broken_symlink(link_name_realpath):
        ic(link_name_realpath, 'exists as a broken symlink. Remove it before trying to make a new symlink. Exiting.')
        sys.exit(1)

    link_name_realpath_folder = b'/'.join(link_name_realpath.split(b'/')[:-1])
    #ceprint("link_name_realpath_folder:", link_name_realpath_folder)
    link_name_realpath_folder_realpath = os.path.realpath(link_name_realpath_folder)
    #ceprint("link_name_realpath_folder_realpath:", link_name_realpath_folder_realpath)
    if not os.path.isdir(link_name_realpath_folder_realpath):
        ic(link_name_realpath_folder_realpath, 'does not exist.')
        raise FileNotFoundError

    relative_target = os.path.relpath(target_realpath, link_name_realpath_folder_realpath)  # relpath does not access the filesystem
    #ceprint("relative_target:", relative_target)
    return relative_target


def create_relative_symlink(*,
                            target: Path,
                            link_name: Path,
                            verbose: bool,
                            debug: bool,
                            ):

    relative_target = calculate_relative_symlink_dest(target=target, link_name=link_name, verbose=verbose, debug=debug)
    link_name_realpath = os.path.realpath(link_name)
    os.symlink(relative_target, link_name_realpath)


def symlink_destination(link): # broken for multi level symlinks
    return os.path.realpath(link)
    #ceprint("this function is unreliable. fix it. it can loop forever.")
    #ceprint(link)
    #"""
    #Return absolute path for the destination of a symlink. This prob should be split into "first dest" and "final dest"
    #"""
    ##assert (os.path.islink(link))
    #p = link
    #while os.path.islink(p):
    #    p = os.path.normpath(os.readlink(link))  # huah?
    #    if os.path.isabs(p):
    #        return p
    #    else:
    #        p = os.path.join(os.path.dirname(link), p)
    #dest = os.path.realpath(p)
    #return dest


def readlinkf(path): # ugly
    p = subprocess.Popen(['readlink', '-f', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    readlink_output, errors = p.communicate()
    readlink_output_clean = readlink_output.strip()
    if errors:
        ic(errors)
    else:
        return readlink_output_clean


def get_abs_path_of_first_symlink_target(path):
    ic(path)
    link_target = os.readlink(path)
    ic(link_target)
    #assert link_target
    link_dir = os.path.dirname(path)
    link_first_target_abs = os.path.join(link_dir, link_target)
    #ceprint(link_first_target_abs)
    link_first_target_abs_normpath = os.path.normpath(link_first_target_abs)
    #ceprint(link_first_target_abs_normpath)
    link_first_target_abs_normpath_abspath = os.path.abspath(link_first_target_abs_normpath)
    ic(link_first_target_abs_normpath_abspath)
    return link_first_target_abs_normpath_abspath


def get_symlink_target_next(path):
    assert os.path.islink(path)
    target = os.readlink(path)
    return target


def get_symlink_target_final(path): #broken for bytes
    if os.path.islink(path):
        target = os.readlink(path)
        target_joined = os.path.join(os.path.dirname(path), target)
        target_file = readlinkf(target_joined).decode('UTF-8')
    else:
        target_file = readlinkf(path).decode('UTF-8')
    return target_file


def is_broken_symlink(path):
    if os.path.islink(path):  # path is a symlink
        return not os.path.exists(path)  # returns False for broken symlinks
    return False  # path isnt a symlink


def is_unbroken_symlink(path):
    if os.path.islink(path):  # path is a symlink
        return os.path.exists(path)  # returns False for broken symlinks
    return False  # path isnt a symlink


def symlink_or_exit(target,
                    link_name,
                    confirm: bool = False,
                    verbose: bool = False,
                    ):
    if verbose:
        ic(target)
        ic(link_name)

    if confirm:
        input("press enter to os.symlink({}, {})".format(target, link_name))

    try:
        os.symlink(target, link_name)
    except Exception as e:
        eprint('Got Exception: %s', e)
        eprint('Unable to symlink link_name: %s to target: %s Exiting.' % (link_name, target))
        raise e


def mkdir_or_exit(folder,
                  confirm: bool,
                  verbose: bool,
                  user: Optional[str] = None,
                  ):
    if verbose:
        ic(folder)
    if confirm:
        input("press enter to os.makedirs({})".format(folder))
    try:
        os.makedirs(folder)
    except FileExistsError:
        assert path_is_dir(folder)
    except Exception as e:
        ic("Exception: %s", e)
        ic("Unable to os.mkdir(%s). Exiting.", folder)
        sys.exit(1)
    if user:
        shutil.chown(folder, user=user, group=user)


def comment_out_line_in_file(*,
                             path,
                             line: str,
                             verbose: bool,
                             debug: bool,
                             startswith: bool = False,
                             ):
    '''
    add a # to the beginning of all instances of line_to_match
    iff there is not already a # preceding line_to_match and
        line_to_match is the only thing on the line
            except possibly a preceeding # and/or whitespace

    if line_to_match is found and all instances are commented return True
    if line_to_match is found and all instances already commented return True
    if line_to_match is not found return False
    '''
    line_to_match = line
    del line
    with open(path, 'r') as rfh:  # bug should hold the fh
        lines = rfh.read().splitlines()
    newlines = []
    for line in lines:
        if line_to_match in line:
            line_stripped = line.strip()
            if line_stripped.startswith('#'):
                newlines.append(line)  # match is already commented out
                continue
            if line_stripped == line:
                newlines.append('#' + line)
                continue
            newlines.append(line)
            continue
        newlines.append(line)
    if lines != newlines:
        with open(path, 'w') as rfh:
            rfh.write('\n'.join(newlines) + '\n')
        return True
    return True


def uncomment_line_in_file(*,
                           path,
                           line: str,
                           verbose: bool,
                           debug: bool,
                           ):
    '''
    remove # from the beginning of all instances of line_to_match
    iff there is already a # preceding line_to_match and
        line_to_match is the only thing on the line
            except possibly a preceeding # and/or whitespace

    if line_to_match is found and all instances uncommented return True
    if line_to_match is found and all instances already uncommented return True
    if line_to_match is not found return False
    '''
    line_to_match = line
    del line
    with open(path, 'r') as rfh:  # bug should hold the fh
        lines = rfh.read().splitlines()
    newlines = []
    uncommented = False
    for line in lines:
        if line_to_match in line:
            line_stripped = line.strip()
            if line_stripped.startswith('#'):
                newlines.append(line[1:])
                uncommented = True
                continue
            if line_stripped == line:
                newlines.append(line)
                uncommented = True
                continue
            newlines.append(line)
            continue
        newlines.append(line)
    if lines != newlines:
        with open(path, 'w') as rfh:
            rfh.write('\n'.join(newlines) + '\n')
        return True
    if uncommented:
        return True
    return False


@retry_on_exception(exception=OSError,
                    errno=errno.ENOSPC,)
def write_line_to_file(*,
                       line,
                       path: Path,
                       verbose: bool,
                       debug: bool,
                       unique: bool = False,
                       make_new_if_necessary: bool = True,
                       unlink_first: bool = False,
                       ) -> bool:
    '''
    Write line to path
    if unique_line == True, write line iff line not in path.
    '''
    path = Path(path).expanduser()
    if isinstance(line, str):
        line = line.encode('UTF8')
    assert isinstance(line, bytes)
    assert line.count(b'\n') == 1
    assert line.endswith(b'\n')

    if unlink_first:
        assert not unique
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass  # race condition
        with open(path, 'xb') as fh:
            if not unique:
                fh.write(line)
                return True

            if line not in fh:
                fh.write(line)
                return True
            return False
    else:
        try:
            with open(path, 'rb+') as fh:
                if not unique:
                    fh.write(line)
                    return True

                if line not in fh:
                    fh.write(line)
                    return True
                return False

        except FileNotFoundError as e:
            if make_new_if_necessary:
                with open(path, 'xb') as fh:
                    fh.write(line)
                    return True
            else:
                raise e


def line_exists_in_file(*,
                        line,
                        file_to_check,
                        verbose: bool,
                        debug: bool,
                        ):
    if isinstance(line, str):
        line = line.encode('UTF8')
    assert isinstance(line, bytes)
    assert line.count(b'\n') == 1
    assert line.endswith(b'\n')
    with open(file_to_check, 'rb') as fh:
        if line in fh:
            return True
        return False


def backup_file_if_exists(file_to_backup):
    timestamp = str(time.time())
    dest_file = file_to_backup + '.bak.' + timestamp
    try:
        with open(file_to_backup, 'rb') as sf:
            with open(dest_file, 'xb') as df:
                copyfileobj(sf, df)
    except FileNotFoundError:
        pass    # skip backup if file does not exist


def read_file_bytes(path):
    with open(path, 'rb') as fh:
        file_bytes = fh.read()
    return file_bytes


def file_exists_nonzero(infile):
    if path_is_file(infile):
        if not empty_file(infile):
            return True
    return False


def get_file_size(filename):
    filename = Path(filename)
    size = filename.lstat().st_size
    #size = os.path.getsize(filename)
    return size


def points_to_data(path: Path,
                   *,
                   empty_ok: bool = False,
                   ):
    assert isinstance(path, Path)
    try:
        size = os.path.getsize(path)  # annoyingly, os.stat(False) == os.stat(0) == os.stat('/dev/stdout')
    except FileNotFoundError:
        return False
    if empty_ok:
        return True
    if size > 0:
        return True
    return False


def empty_file(path: Path):
    assert isinstance(path, Path)
    if not path_exists(path):
        #return True #hm
        raise FileNotFoundError
    if os.path.isfile(path):
        if os.path.getsize(path) == 0:
            return True
    return False


class UnableToSetImmutableError(ValueError):
    pass


def make_file_immutable(infile):
    command = "sudo /usr/bin/chattr +i " + infile
    os.system(command)
    result_command = "/usr/bin/lsattr " + infile
    result = os.popen(result_command).read()
    if result[4] != 'i':
        eprint('make_file_immutable(%s) failed. Exiting')
        raise UnableToSetImmutableError(command)
    return True


def rename_or_exit(src, dest):
    try:
        os.rename(src, dest)
    except Exception as e:
        eprint("Got Exception: %s", e)
        eprint("Unable to rename src: %s to dest: %s Exiting.", src, dest)
        sys.exit(1)


def move_file_only_if_new_or_exit(source, dest):
    try:
        shutil.move(source, dest)   #todo: fix race condition beacuse shutil.move overwrites existing dest
    except Exception as e:
        eprint("Exception: %s", e)
        eprint("move_file_only_if_new_or_exit(): error. Exiting.")
        sys.exit(1)


def write_file(infile, data):
    assert len(data) > 0
    #On Py3 we have one text type, str which holds Unicode data and two byte types; bytes and bytearray.
    if isinstance(data, str): #unicode in py3
        with open(infile, "x", encoding='utf-8') as fd:
            fd.write(data)
    elif isinstance(data, bytes):
        with open(infile, "xb") as fd:
            fd.write(data)
    else:
        eprint("Unknown type for data: %s. Could not create python file descriptor: %s Exiting.", type(data), infile)
        os._exit(1)


def is_regular_file(path):
    mode = os.stat(path, follow_symlinks=False)[stat.ST_MODE]
    if stat.S_ISREG(mode):
        return True
    return False


#def get_file_type(path):
#    line_id = magic.from_file(path)
#    return line_id


def combine_files(source: Path, destination: Path, buffer=65535):
    assert is_regular_file(source)
    assert is_regular_file(destination)
    with open(source, "rb") as sfh:
        fcntl.flock(sfh, fcntl.LOCK_SH)
        with open(destination, "ab") as dfh:
            fcntl.flock(dfh, fcntl.LOCK_EX)
            while True:
                data = sfh.read(buffer)
                if data:
                    dfh.write(data)
                else:
                    break


# todo
# https://github.com/MostAwesomeDude/betterpath/blob/master/bp/filepath.py
# https://github.com/twisted/twisted/blob/trunk/twisted/python/filepath.py
# https://stackoverflow.com/questions/1430446/create-a-temporary-fifo-named-pipe-in-python
@contextmanager
def temp_fifo(verbose: bool = False,
              ):
    """Context Manager for creating named pipes with temporary names."""
    tmpdir = tempfile.mkdtemp()
    filename = os.path.join(tmpdir, 'fifo')  # Temporary filename
    if verbose:
        ic(filename)
    os.mkfifo(filename)  # Create FIFO
    try:
        yield filename
    finally:
        os.unlink(filename)  # Remove file
        os.rmdir(tmpdir)  # Remove directory


def get_free_space_at_path(*,
                           path: Path,
                           verbose: bool,
                           debug: bool,
                           ):
    assert isinstance(path, Path)
    free_bytes = os.statvfs(path).f_ffree
    if verbose:
        ic(path, free_bytes)
    assert isinstance(free_bytes, int)
    return free_bytes


def get_path_with_most_free_space(*,
                                  pathlist: list[Path],
                                  verbose: bool,
                                  debug: bool,
                                  ):
    ic(pathlist)
    assert isinstance(pathlist, (list, tuple))
    largest: Optional[tuple[int, Path]] = None
    for path in pathlist:
        free_bytes: int = get_free_space_at_path(path=path, verbose=verbose, debug=debug,)
        ic(path, free_bytes)
        if not largest:
            largest = (free_bytes, path)
            continue
        if free_bytes > largest[0]:
            largest = (free_bytes, path)
    if verbose:
        ic(largest)
    ic(largest)
    if largest:
        return Path(largest[1])
    raise ValueError


def longest_prefix(iter0, iter1):
    '''
    Returns the longest common prefix of the given two iterables.
    '''
    _longest_prefix = []
    for (elmt0, elmt1) in zip(iter0, iter1):
        if elmt0 != elmt1:
            break
        _longest_prefix.append(elmt0)
    return _longest_prefix


def paths_are_identical(path1: Path,
                        path2: Path,
                        *,
                        time: bool = False,
                        perms: bool = False,
                        verbose: bool = False,
                        ):

    assert isinstance(path1, Path)
    assert isinstance(path2, Path)
    if time or perms:
        raise NotImplementedError

    path1_lstat = os.lstat(path1)
    path2_lstat = os.lstat(path2)

    path1_type = stat.S_IFMT(path1_lstat.st_mode)
    path2_type = stat.S_IFMT(path2_lstat.st_mode)

    if path1_type != path2_type:
        ic(path1, path1_type)
        ic(path2, path2_type)
        return False

    if path1_type in [32768, 24576]:  # file or device
        path1_hash = sha3_256_hash_file(path1)
        path2_hash = sha3_256_hash_file(path2)
        if verbose:
            ic(path1_hash)
            ic(path2_hash)

        if path1_hash != path2_hash:
            ic(path1, path1_hash)
            ic(path2, path2_hash)
            return False

    if path1_type == 40960:     # symlink
        path1_target = os.readlink(path1)
        path2_target = os.readlink(path2)
        if verbose:
            ic(path1_target)
            ic(path2_target)

        if path1_target != path2_target:
            ic(path1, path1_target)
            ic(path2, path2_target)
            return False

    return True


def path_is_dir_or_symlink_to_dir(path):
    # unlike os.path.exists(False), os.path.isdir(False) returns False
    if os.path.isdir(path): # returns False if it's a symlink to a file
        return True
    return False


def path_exists(path):
    if path is None:
        return False
    return os.path.lexists(path) #  returns True for broken symlinks


def path_is_block_special(path,
                          follow_symlinks: bool = False,
                          ):
    if path_exists(path):
        mode = os.stat(path, follow_symlinks=follow_symlinks).st_mode
        if stat.S_ISBLK(mode):
            return True
    return False


def path_is_file(path: Path):
    if not isinstance(path, Path):
        path = Path(path).expanduser()
    if path.is_symlink():
        return False

    # unlike os.path.exists(False), os.path.isfile(False) returns False so no need to call path_exists() first.
    if os.path.isfile(path):
        return True
    return False


def check_or_create_dir(folder, confirm=True):
    #assert isinstance(folder, bytes)
    if not os.path.isdir(folder):
        if confirm:
            eprint("The folder:")
            eprint(folder)
            eprint("does not exist. Type yes to create it and continue, otherwise exiting:")
            eprint("make dir:")
            eprint(folder, end=None)
            make_folder_answer = input(": ")
            if make_folder_answer.lower() != "yes":
                eprint("Exiting before mkdir.")
                os._exit(1)
        create_dir(folder)
        return True


def create_dir(folder):
    try:
        os.makedirs(folder, exist_ok=True)
    except FileExistsError:
        pass


def chdir_or_exit(targetdir):
    try:
        os.chdir(targetdir)
    except Exception as e:
        eprint("Exception:", e)
        eprint("Unable to os.chdir(%s). Enxiting.", targetdir)
        os._exit(1)
    return True


def remove_empty_folders(path, remove_root=True, verbose=False):
    if not os.path.isdir(path):
        return

    # remove empty subfolders
    files = os.listdir(path)
    if len(files):
        for f in files:
            fullpath = os.path.join(path, f)
            if os.path.isdir(fullpath):
                if not os.path.islink(fullpath):
                    remove_empty_folders(fullpath)

    # if folder empty, delete it
    files = os.listdir(path)
    if len(files) == 0 and remove_root:
        if verbose:
            eprint("removing empty folder:", path)
        os.rmdir(path)


def really_is_dir(path: Path):
    if path.is_symlink():
        return False
    if path.is_dir(): # is_dir() answers False for broken symlinks, and crashes with an OSError on self-symlinks
        return True
    return False


@click.command()
@click.argument("paths", type=str, nargs=-1)
@click.option('--verbose', is_flag=True)
@click.option('--debug', is_flag=True)
@click.pass_context
def cli(ctx,
        paths: tuple[str],
        sysskel: str,
        verbose: bool,
        debug: bool,
        ):

    ctx.ensure_object(dict)
    null, end, verbose, debug = nevd(ctx=ctx,
                                     printn=False,
                                     ipython=False,
                                     verbose=verbose,
                                     debug=debug,)

    iterator = paths

    for index, path in enumerate_input(iterator=iterator,
                                       debug=debug,
                                       verbose=verbose,):
        path = Path(path).expanduser()

        if verbose:  # or simulate:
            ic(index, path)
