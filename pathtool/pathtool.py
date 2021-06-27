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
from asserttool import verify
from hasher import sha3_256_hash_file
from retry_on_exception import retry_on_exception

signal(SIGPIPE,SIG_DFL)
from typing import ByteString
from typing import Generator
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence

from enumerate_input import enumerate_input

#from with_chdir import chdir

#from pathtool import path_is_block_special
#from getdents import files
#from prettytable import PrettyTable
#output_table = PrettyTable()



def eprint(*args, **kwargs):
    if 'file' in kwargs.keys():
        kwargs.pop('file')
    print(*args, file=sys.stderr, **kwargs)


try:
    from icecream import ic  # https://github.com/gruns/icecream
except ImportError:
    ic = eprint




def validate_slice(slice_syntax):
    assert isinstance(slice_syntax, str)
    for c in slice_syntax:
        if c not in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '[', ']', ':']:
            raise ValueError(slice_syntax)
    return slice_syntax


#@with_plugins(iter_entry_points('click_command_tree'))
#@click.group()
#@click.option('--verbose', is_flag=True)
#@click.option('--debug', is_flag=True)
#@click.pass_context
#def cli(ctx,
#        verbose: bool,
#        debug: bool,
#        ):
#
#    ctx.ensure_object(dict)
#    ctx.obj['verbose'] = verbose
#    ctx.obj['debug'] = debug


def nl_iff_tty(*, printn, ipython):
    null = not printn
    end = '\n'
    if null:
        end = '\x00'
    if sys.stdout.isatty():
        end = '\n'
        assert not ipython
    return end


def nevd(*, ctx,
         printn: bool,
         ipython: bool,
         verbose: bool,
         debug: bool,
         ):

    null = not printn
    end = nl_iff_tty(printn=printn, ipython=False)
    if verbose:
        ctx.obj['verbose'] = verbose
    verbose = ctx.obj['verbose']
    if debug:
        ctx.obj['debug'] = debug
    debug = ctx.obj['debug']

    return null, end, verbose, debug


# DONT CHANGE FUNC NAME
@click.command()
@click.argument("paths", type=str, nargs=-1)
@click.argument("sysskel",
                type=click.Path(exists=False,
                                dir_okay=True,
                                file_okay=False,
                                path_type=str,
                                allow_dash=False,),
                nargs=1,
                required=True,)
@click.argument("slice_syntax", type=validate_slice, nargs=1)
#@click.option('--add', is_flag=True)
@click.option('--verbose', is_flag=True)
@click.option('--debug', is_flag=True)
@click.option('--simulate', is_flag=True)
@click.option('--ipython', is_flag=True)
@click.option('--count', is_flag=True)
@click.option('--skip', type=int, default=False)
@click.option('--head', type=int, default=False)
@click.option('--tail', type=int, default=False)
@click.option("--printn", is_flag=True)
#@click.option("--progress", is_flag=True)
@click.pass_context
def cli(ctx,
        paths,
        sysskel: str,
        slice_syntax: str,
        verbose: bool,
        debug: bool,
        simulate: bool,
        ipython: bool,
        count: bool,
        skip: int,
        head: int,
        tail: int,
        printn: bool,
        ):

    ctx.ensure_object(dict)
    null = not printn
    end = nl_iff_tty(printn=printn, ipython=ipython)
    null, end, verbose, debug = nevd(ctx=ctx,
                                     printn=printn,
                                     ipython=False,
                                     verbose=verbose,
                                     debug=debug,)

    #progress = False
    #if (verbose or debug):
    #    progress = False

    #if verbose:
    #    ctx.obj['verbose'] = verbose
    #verbose = ctx.obj['verbose']
    #if debug:
    #    ctx.obj['debug'] = debug
    #debug = ctx.obj['debug']

    #ctx.obj['end'] = end
    #ctx.obj['null'] = null
    #ctx.obj['progress'] = progress
    ctx.obj['count'] = count
    ctx.obj['skip'] = skip
    ctx.obj['head'] = head
    ctx.obj['tail'] = tail

    #global APP_NAME
    #config, config_mtime = click_read_config(click_instance=click,
    #                                         app_name=APP_NAME,
    #                                         verbose=verbose,
    #                                         debug=debug,)
    #if verbose:
    #    ic(config, config_mtime)

    #if add:
    #    section = "test_section"
    #    key = "test_key"
    #    value = "test_value"
    #    config, config_mtime = click_write_config_entry(click_instance=click,
    #                                                    app_name=APP_NAME,
    #                                                    section=section,
    #                                                    key=key,
    #                                                    value=value,
    #                                                    verbose=verbose,
    #                                                    debug=debug,)
    #    if verbose:
    #        ic(config)

    iterator = paths

    for index, path in enumerate_input(iterator=iterator,
                                       null=null,
                                       progress=False,
                                       skip=skip,
                                       head=head,
                                       tail=tail,
                                       debug=debug,
                                       verbose=verbose,):
        path = Path(path).expanduser()

        if verbose:  # or simulate:
            ic(index, path)
        #if count:
        #    if count > (index + 1):
        #        ic(count)
        #        sys.exit(0)

        #if simulate:
        #    continue

        with open(path, 'rb') as fh:
            path_bytes_data = fh.read()

        if not count:
            print(path, end=end)

    if count:
        print(index + 1, end=end)

#        if ipython:
#            import IPython; IPython.embed()

#@cli.command()
#@click.argument("urls", type=str, nargs=-1)
#@click.option('--verbose', is_flag=True)
#@click.option('--debug', is_flag=True)
#@click.pass_context
#def some_command(ctx,
#                 urls,
#                 verbose: bool,
#                 debug: bool,
#                 ):
#    if verbose:
#        ctx.obj['verbose'] = verbose
#    verbose = ctx.obj['verbose']
#    if debug:
#        ctx.obj['debug'] = debug
#    debug = ctx.obj['debug']
#
#    iterator = urls
#    for index, url in enumerate_input(iterator=iterator,
#                                      null=ctx.obj['null'],
#                                      progress=ctx.obj['progress'],
#                                      skip=ctx.obj['skip'],
#                                      head=ctx.obj['head'],
#                                      tail=ctx.obj['tail'],
#                                      debug=ctx.obj['debug'],
#                                      verbose=ctx.obj['verbose'],):
#
#        if ctx.obj['verbose']:
#            ic(index, url)


#!/usr/bin/env python3
# tab-width:4
# pylint: disable=missing-docstring




def comment_out_line_in_file(*,
                             file_path,
                             line_to_match: str,
                             verbose: bool,
                             debug: bool,):
    '''
    add a # to the beginning of all instances of line_to_match
    iff there is not already a # preceding line_to_match and
        line_to_match is the only thing on the line
            except possibly a preceeding # and/or whitespace

    if line_to_match is found and all instances are commented return True
    if line_to_match is found and all instances already commented return True
    if line_to_match is not found return False
    '''
    with open(file_path, 'r') as rfh:  # bug should hold the fh
        lines = rfh.read().splitlines()
    newlines = []
    #commented = False
    for line in lines:
        if line_to_match in line:
            line_stripped = line.strip()
            if line_stripped.startswith('#'):
                newlines.append(line)
                continue
            if line_stripped == line:
                newlines.append('#' + line)
                continue
            newlines.append(line)
            continue
        newlines.append(line)
    if lines != newlines:
        with open(file_path, 'w') as rfh:
            rfh.write('\n'.join(newlines) + '\n')
        return True
    return True


def uncomment_line_in_file(*,
                           file_path,
                           line_to_match: str,
                           verbose: bool,
                           debug: bool,):
    '''
    remove # from the beginning of all instances of line_to_match
    iff there is already a # preceding line_to_match and
        line_to_match is the only thing on the line
            except possibly a preceeding # and/or whitespace

    if line_to_match is found and all instances uncommented return True
    if line_to_match is found and all instances already uncommented return True
    if line_to_match is not found return False
    '''
    with open(file_path, 'r') as rfh:  # bug should hold the fh
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
        with open(file_path, 'w') as rfh:
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
                       make_new: bool = True,
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
        if make_new:
            with open(path, 'xb') as fh:
                fh.write(line)
                return True
        else:
            raise e


def line_exists_in_file(*,
                        line,
                        file_to_check,
                        verbose: bool,
                        debug: bool,):
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


def get_block_device_size(device):
    assert Path(device).is_block_device()
    fd = os.open(device, os.O_RDONLY)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)


def get_file_size(filename):
    filename = Path(filename)
    size = filename.lstat().st_size
    #size = os.path.getsize(filename)
    return size


def points_to_data(fpath, empty_ok=False):
    assert isinstance(fpath, (str, bytes, Path))
    try:
        size = os.path.getsize(fpath)  # annoyingly, os.stat(False) == os.stat(0) == os.stat('/dev/stdout')
    except FileNotFoundError:
        return False
    if empty_ok:
        return True
    if size > 0:
        return True
    return False


def empty_file(fpath):
    if not path_exists(fpath):
        #return True #hm
        raise FileNotFoundError
    if os.path.isfile(fpath):
        if os.path.getsize(fpath) == 0:
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
        os._exit(1)


def move_file_only_if_new_or_exit(source, dest):
    try:
        shutil.move(source, dest)   #todo: fix race condition beacuse shutil.move overwrites existing dest
    except Exception as e:
        eprint("Exception: %s", e)
        eprint("move_file_only_if_new_or_exit(): error. Exiting.")
        os._exit(1)


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


def combine_files(source, destination, buffer=65535):
    verify(is_regular_file(source))
    verify(is_regular_file(destination))
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
def temp_fifo(verbose=False):
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
                           debug: bool,):
    assert isinstance(path, Path)
    free_bytes = os.statvfs(path).f_ffree
    if verbose:
        ic(path, free_bytes)
    return free_bytes


def get_path_with_most_free_space(*,
                                  pathlist: [Path],
                                  verbose: bool,
                                  debug: bool,):
    ic(pathlist)
    largest = ()
    for path in pathlist:
        free_bytes = get_free_space_at_path(path=path, verbose=verbose, debug=debug,)
        ic(path, free_bytes)
        if not largest:
            largest = (free_bytes, path)
            continue
        if free_bytes > largest[0]:
            largest = (free_bytes, path)
    if verbose:
        ic(largest)
    ic(largest)
    return Path(largest[1])


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


def paths_are_identical(path1,
                        path2,
                        *,
                        time: bool = False,
                        perms: bool = False,
                        verbose: bool = False,):
    verify(isinstance(path1, Path))
    verify(isinstance(path2, Path))
    if time or perms:
        raise NotImplementedError

    path1_lstat = os.lstat(path1)
    path2_lstat = os.lstat(path2)

    path1_type = stat.S_IFMT(path1_lstat.st_mode)
    path2_type = stat.S_IFMT(path2_lstat.st_mode)
    #if verbose:
    #    ic(path1_type)
    #    ic(path2_type)

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


#def common_prefix_path(path0, path1):
#    return os.path.join(*longest_prefix(components(path0), components(path1)))

# For Unix:
#assert common_prefix_path('/', '/usr') == '/'
#assert common_prefix_path('/usr/var1/log/', '/usr/var2/log/') == '/usr'
#assert common_prefix_path('/usr/var/log1/', '/usr/var/log2/') == '/usr/var'
#assert common_prefix_path('/usr/var/log', '/usr/var/log2') == '/usr/var'
#assert common_prefix_path('/usr/var/log', '/usr/var/log') == '/usr/var/log'
# Only for Windows:
# assert common_prefix_path(r'C:\Programs\Me', r'C:\Programs') == r'C:\Programs'


def path_is_dir_or_symlink_to_dir(path):
    # unlike os.path.exists(False), os.path.isdir(False) returns False
    if os.path.isdir(path): # returns False if it's a symlink to a file
        return True
    return False


#def path_is_dir(path):
#    if os.path.isdir(path): #could still be a symlink
#        if os.path.islink(path):
#            return False
#        return True
#    return False


def path_exists(path):
    if path is None:
        return False
    return os.path.lexists(path) #returns True for broken symlinks


def path_is_block_special(path, follow_symlinks=False):
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
    if os.path.isfile(path): #unlike os.path.exists(False), os.path.isfile(False) returns False so no need to call path_exists() first.
        return True
    return False
