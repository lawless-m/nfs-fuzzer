"""
NFS Version 3 Protocol Definitions for boofuzz

RFC 1813 - NFS Version 3 Protocol Specification

This module provides NFSv3 procedure definitions for fuzzing NFS servers.
"""

from boofuzz import (
    Block,
    Bytes,
    DWord,
    QWord,
    Request,
    Size,
    Static,
    String,
    BIG_ENDIAN,
)

from .sunrpc import (
    PROG_NFS,
    rpc_call_request,
    xdr_pad_length,
    xdr_padded_bytes,
)

# =============================================================================
# NFSv3 Constants (RFC 1813)
# =============================================================================

NFS_V3 = 3

# NFSv3 Procedures
NFSPROC3_NULL = 0
NFSPROC3_GETATTR = 1
NFSPROC3_SETATTR = 2
NFSPROC3_LOOKUP = 3
NFSPROC3_ACCESS = 4
NFSPROC3_READLINK = 5
NFSPROC3_READ = 6
NFSPROC3_WRITE = 7
NFSPROC3_CREATE = 8
NFSPROC3_MKDIR = 9
NFSPROC3_SYMLINK = 10
NFSPROC3_MKNOD = 11
NFSPROC3_REMOVE = 12
NFSPROC3_RMDIR = 13
NFSPROC3_RENAME = 14
NFSPROC3_LINK = 15
NFSPROC3_READDIR = 16
NFSPROC3_READDIRPLUS = 17
NFSPROC3_FSSTAT = 18
NFSPROC3_FSINFO = 19
NFSPROC3_PATHCONF = 20
NFSPROC3_COMMIT = 21

# Access bits for ACCESS procedure
ACCESS3_READ = 0x0001
ACCESS3_LOOKUP = 0x0002
ACCESS3_MODIFY = 0x0004
ACCESS3_EXTEND = 0x0008
ACCESS3_DELETE = 0x0010
ACCESS3_EXECUTE = 0x0020

# Write stable modes
UNSTABLE = 0
DATA_SYNC = 1
FILE_SYNC = 2

# Create modes
UNCHECKED = 0
GUARDED = 1
EXCLUSIVE = 2

# File types
NF3REG = 1  # Regular file
NF3DIR = 2  # Directory
NF3BLK = 3  # Block device
NF3CHR = 4  # Character device
NF3LNK = 5  # Symbolic link
NF3SOCK = 6  # Socket
NF3FIFO = 7  # FIFO

# Maximum sizes
NFS3_FHSIZE = 64  # Maximum file handle size


# =============================================================================
# XDR Data Types
# =============================================================================


def fhandle3(name: str, handle_data: bytes = None) -> Block:
    """
    Create an NFSv3 file handle (fhandle3).

    fhandle3 is a variable-length opaque up to 64 bytes:
        length (4 bytes) + data (up to 64 bytes) + padding

    Args:
        name: Block name
        handle_data: File handle bytes (default: 32 random-ish bytes for fuzzing)

    Returns:
        Block containing the file handle
    """
    if handle_data is None:
        # Default handle for fuzzing - 32 bytes of recognizable pattern
        handle_data = b"\xde\xad\xbe\xef" * 8

    padded = xdr_padded_bytes(handle_data)

    return Block(
        name=name,
        children=(
            DWord(
                name=f"{name}_length",
                default_value=len(handle_data),
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            Bytes(
                name=f"{name}_data",
                default_value=padded,
                size=len(padded),
                fuzzable=True,
            ),
        ),
    )


def filename3(name: str, filename: str = "testfile") -> Block:
    """
    Create an NFSv3 filename (XDR string).

    filename3 is an XDR string:
        length (4 bytes) + characters + padding

    Args:
        name: Block name
        filename: Default filename string

    Returns:
        Block containing the filename
    """
    name_bytes = filename.encode("utf-8")
    padded = xdr_padded_bytes(name_bytes)

    return Block(
        name=name,
        children=(
            DWord(
                name=f"{name}_length",
                default_value=len(name_bytes),
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            Bytes(
                name=f"{name}_data",
                default_value=padded,
                size=len(padded),
                fuzzable=True,
            ),
        ),
    )


def dirop3(name: str, handle_data: bytes = None, filename: str = "testfile") -> Block:
    """
    Create an NFSv3 directory operation argument (dirop3).

    dirop3 combines a directory file handle with a filename:
        fhandle3 (directory handle) + filename3

    Args:
        name: Block name
        handle_data: Directory file handle bytes
        filename: Name to look up in directory

    Returns:
        Block containing directory operation
    """
    return Block(
        name=name,
        children=(
            fhandle3(name=f"{name}_dir_handle", handle_data=handle_data),
            filename3(name=f"{name}_name", filename=filename),
        ),
    )


def nfstime3(name: str, seconds: int = 0, nseconds: int = 0) -> Block:
    """
    Create an NFSv3 timestamp (nfstime3).

    Args:
        name: Block name
        seconds: Seconds since epoch
        nseconds: Nanoseconds

    Returns:
        Block containing timestamp
    """
    return Block(
        name=name,
        children=(
            DWord(
                name=f"{name}_seconds",
                default_value=seconds,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            DWord(
                name=f"{name}_nseconds",
                default_value=nseconds,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
        ),
    )


# =============================================================================
# NFSv3 Procedure Requests
# =============================================================================


def nfs3_null() -> Request:
    """
    NFSv3 NULL procedure (procedure 0).

    Takes no arguments, returns void. Used for connectivity testing.
    """
    return rpc_call_request(
        name="NFS3-NULL",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_NULL,
    )


def nfs3_getattr(handle_data: bytes = None) -> Request:
    """
    NFSv3 GETATTR procedure (procedure 1).

    Args:
        GETATTR3args:
            fhandle3 object - file handle to get attributes for

    Target for fuzzing: malformed file handles, invalid lengths.
    """
    return rpc_call_request(
        name="NFS3-GETATTR",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_GETATTR,
        args_children=(fhandle3(name="NFS3-GETATTR_fhandle", handle_data=handle_data),),
    )


def nfs3_lookup(dir_handle: bytes = None, filename: str = "testfile") -> Request:
    """
    NFSv3 LOOKUP procedure (procedure 3).

    Args:
        LOOKUP3args:
            dirop3 what - directory handle + name to look up

    Target for fuzzing: long filenames, special characters, path traversal.
    """
    return rpc_call_request(
        name="NFS3-LOOKUP",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_LOOKUP,
        args_children=(
            dirop3(name="NFS3-LOOKUP_what", handle_data=dir_handle, filename=filename),
        ),
    )


def nfs3_access(handle_data: bytes = None, access_bits: int = 0x3F) -> Request:
    """
    NFSv3 ACCESS procedure (procedure 4).

    Args:
        ACCESS3args:
            fhandle3 object - file handle
            uint32 access - access bits to check

    Target for fuzzing: invalid access bit combinations.
    """
    return rpc_call_request(
        name="NFS3-ACCESS",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_ACCESS,
        args_children=(
            fhandle3(name="NFS3-ACCESS_fhandle", handle_data=handle_data),
            DWord(
                name="NFS3-ACCESS_access",
                default_value=access_bits,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
        ),
    )


def nfs3_read(
    handle_data: bytes = None,
    offset: int = 0,
    count: int = 4096,
) -> Request:
    """
    NFSv3 READ procedure (procedure 6).

    Args:
        READ3args:
            fhandle3 file - file handle
            offset3 offset - byte offset (uint64)
            count3 count - bytes to read (uint32)

    Target for fuzzing: huge offsets, count overflow, offset+count overflow.
    """
    return rpc_call_request(
        name="NFS3-READ",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_READ,
        args_children=(
            fhandle3(name="NFS3-READ_fhandle", handle_data=handle_data),
            QWord(
                name="NFS3-READ_offset",
                default_value=offset,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            DWord(
                name="NFS3-READ_count",
                default_value=count,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
        ),
    )


def nfs3_write(
    handle_data: bytes = None,
    offset: int = 0,
    count: int = 0,
    stable: int = FILE_SYNC,
    data: bytes = b"",
) -> Request:
    """
    NFSv3 WRITE procedure (procedure 7).

    Args:
        WRITE3args:
            fhandle3 file - file handle
            offset3 offset - byte offset (uint64)
            count3 count - bytes to write (uint32)
            stable_how stable - write stability (UNSTABLE=0, DATA_SYNC=1, FILE_SYNC=2)
            opaque data<> - data to write

    Target for fuzzing: count mismatch with data length, huge offsets.
    """
    data_padded = xdr_padded_bytes(data)

    return rpc_call_request(
        name="NFS3-WRITE",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_WRITE,
        args_children=(
            fhandle3(name="NFS3-WRITE_fhandle", handle_data=handle_data),
            QWord(
                name="NFS3-WRITE_offset",
                default_value=offset,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            DWord(
                name="NFS3-WRITE_count",
                default_value=count,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            DWord(
                name="NFS3-WRITE_stable",
                default_value=stable,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            # Data as XDR opaque (length + data + padding)
            DWord(
                name="NFS3-WRITE_data_length",
                default_value=len(data),
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            Bytes(
                name="NFS3-WRITE_data",
                default_value=data_padded,
                size=len(data_padded),
                fuzzable=True,
            ),
        ),
    )


def nfs3_readdir(
    handle_data: bytes = None,
    cookie: int = 0,
    cookieverf: bytes = None,
    count: int = 4096,
) -> Request:
    """
    NFSv3 READDIR procedure (procedure 16).

    Args:
        READDIR3args:
            fhandle3 dir - directory handle
            cookie3 cookie - position cookie (uint64)
            cookieverf3 cookieverf - cookie verifier (8 bytes)
            count3 count - max bytes to return

    Target for fuzzing: cookie handling, state confusion.
    """
    if cookieverf is None:
        cookieverf = b"\x00" * 8

    return rpc_call_request(
        name="NFS3-READDIR",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_READDIR,
        args_children=(
            fhandle3(name="NFS3-READDIR_dir", handle_data=handle_data),
            QWord(
                name="NFS3-READDIR_cookie",
                default_value=cookie,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            Bytes(
                name="NFS3-READDIR_cookieverf",
                default_value=cookieverf,
                size=8,
                fuzzable=True,
            ),
            DWord(
                name="NFS3-READDIR_count",
                default_value=count,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
        ),
    )


def nfs3_readdirplus(
    handle_data: bytes = None,
    cookie: int = 0,
    cookieverf: bytes = None,
    dircount: int = 4096,
    maxcount: int = 8192,
) -> Request:
    """
    NFSv3 READDIRPLUS procedure (procedure 17).

    Args:
        READDIRPLUS3args:
            fhandle3 dir - directory handle
            cookie3 cookie - position cookie (uint64)
            cookieverf3 cookieverf - cookie verifier (8 bytes)
            count3 dircount - max bytes of directory info
            count3 maxcount - max bytes total (including attributes)

    Target for fuzzing: directory enumeration, memory allocation.
    """
    if cookieverf is None:
        cookieverf = b"\x00" * 8

    return rpc_call_request(
        name="NFS3-READDIRPLUS",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_READDIRPLUS,
        args_children=(
            fhandle3(name="NFS3-READDIRPLUS_dir", handle_data=handle_data),
            QWord(
                name="NFS3-READDIRPLUS_cookie",
                default_value=cookie,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            Bytes(
                name="NFS3-READDIRPLUS_cookieverf",
                default_value=cookieverf,
                size=8,
                fuzzable=True,
            ),
            DWord(
                name="NFS3-READDIRPLUS_dircount",
                default_value=dircount,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            DWord(
                name="NFS3-READDIRPLUS_maxcount",
                default_value=maxcount,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
        ),
    )


def nfs3_fsstat(handle_data: bytes = None) -> Request:
    """
    NFSv3 FSSTAT procedure (procedure 18).

    Args:
        FSSTAT3args:
            fhandle3 fsroot - file system root handle

    Returns file system statistics.
    """
    return rpc_call_request(
        name="NFS3-FSSTAT",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_FSSTAT,
        args_children=(fhandle3(name="NFS3-FSSTAT_fsroot", handle_data=handle_data),),
    )


def nfs3_fsinfo(handle_data: bytes = None) -> Request:
    """
    NFSv3 FSINFO procedure (procedure 19).

    Args:
        FSINFO3args:
            fhandle3 fsroot - file system root handle

    Returns file system info (max read/write sizes, etc).
    """
    return rpc_call_request(
        name="NFS3-FSINFO",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_FSINFO,
        args_children=(fhandle3(name="NFS3-FSINFO_fsroot", handle_data=handle_data),),
    )


def nfs3_pathconf(handle_data: bytes = None) -> Request:
    """
    NFSv3 PATHCONF procedure (procedure 20).

    Args:
        PATHCONF3args:
            fhandle3 object - file handle

    Returns POSIX pathconf info for the file.
    """
    return rpc_call_request(
        name="NFS3-PATHCONF",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_PATHCONF,
        args_children=(fhandle3(name="NFS3-PATHCONF_object", handle_data=handle_data),),
    )


def nfs3_commit(
    handle_data: bytes = None,
    offset: int = 0,
    count: int = 0,
) -> Request:
    """
    NFSv3 COMMIT procedure (procedure 21).

    Args:
        COMMIT3args:
            fhandle3 file - file handle
            offset3 offset - byte offset to start commit
            count3 count - bytes to commit (0 = all)

    Commits cached data to stable storage.
    """
    return rpc_call_request(
        name="NFS3-COMMIT",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_COMMIT,
        args_children=(
            fhandle3(name="NFS3-COMMIT_fhandle", handle_data=handle_data),
            QWord(
                name="NFS3-COMMIT_offset",
                default_value=offset,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            DWord(
                name="NFS3-COMMIT_count",
                default_value=count,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
        ),
    )


def nfs3_create(
    dir_handle: bytes = None,
    filename: str = "newfile",
    create_mode: int = UNCHECKED,
) -> Request:
    """
    NFSv3 CREATE procedure (procedure 8).

    Args:
        CREATE3args:
            dirop3 where - directory + filename
            createhow3 how - creation mode and attributes

    Creates a new regular file.
    """
    return rpc_call_request(
        name="NFS3-CREATE",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_CREATE,
        args_children=(
            dirop3(name="NFS3-CREATE_where", handle_data=dir_handle, filename=filename),
            # createhow3: mode (UNCHECKED/GUARDED/EXCLUSIVE)
            DWord(
                name="NFS3-CREATE_mode",
                default_value=create_mode,
                endian=BIG_ENDIAN,
                fuzzable=True,
            ),
            # For UNCHECKED/GUARDED, follow with sattr3 (simplified - all fields "don't set")
            # set_mode = FALSE
            DWord(name="NFS3-CREATE_set_mode", default_value=0, endian=BIG_ENDIAN),
            # set_uid = FALSE
            DWord(name="NFS3-CREATE_set_uid", default_value=0, endian=BIG_ENDIAN),
            # set_gid = FALSE
            DWord(name="NFS3-CREATE_set_gid", default_value=0, endian=BIG_ENDIAN),
            # set_size = FALSE
            DWord(name="NFS3-CREATE_set_size", default_value=0, endian=BIG_ENDIAN),
            # set_atime = DONT_CHANGE (0)
            DWord(name="NFS3-CREATE_set_atime", default_value=0, endian=BIG_ENDIAN),
            # set_mtime = DONT_CHANGE (0)
            DWord(name="NFS3-CREATE_set_mtime", default_value=0, endian=BIG_ENDIAN),
        ),
    )


def nfs3_remove(dir_handle: bytes = None, filename: str = "testfile") -> Request:
    """
    NFSv3 REMOVE procedure (procedure 12).

    Args:
        REMOVE3args:
            dirop3 object - directory handle + filename to remove

    Removes a file from a directory.
    """
    return rpc_call_request(
        name="NFS3-REMOVE",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_REMOVE,
        args_children=(
            dirop3(
                name="NFS3-REMOVE_object", handle_data=dir_handle, filename=filename
            ),
        ),
    )


def nfs3_mkdir(dir_handle: bytes = None, dirname: str = "newdir") -> Request:
    """
    NFSv3 MKDIR procedure (procedure 9).

    Args:
        MKDIR3args:
            dirop3 where - parent directory + new directory name
            sattr3 attributes - initial attributes

    Creates a new directory.
    """
    return rpc_call_request(
        name="NFS3-MKDIR",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_MKDIR,
        args_children=(
            dirop3(name="NFS3-MKDIR_where", handle_data=dir_handle, filename=dirname),
            # sattr3 - all "don't set"
            DWord(name="NFS3-MKDIR_set_mode", default_value=0, endian=BIG_ENDIAN),
            DWord(name="NFS3-MKDIR_set_uid", default_value=0, endian=BIG_ENDIAN),
            DWord(name="NFS3-MKDIR_set_gid", default_value=0, endian=BIG_ENDIAN),
            DWord(name="NFS3-MKDIR_set_size", default_value=0, endian=BIG_ENDIAN),
            DWord(name="NFS3-MKDIR_set_atime", default_value=0, endian=BIG_ENDIAN),
            DWord(name="NFS3-MKDIR_set_mtime", default_value=0, endian=BIG_ENDIAN),
        ),
    )


def nfs3_rmdir(dir_handle: bytes = None, dirname: str = "testdir") -> Request:
    """
    NFSv3 RMDIR procedure (procedure 13).

    Args:
        RMDIR3args:
            dirop3 object - parent directory handle + directory name to remove

    Removes a directory.
    """
    return rpc_call_request(
        name="NFS3-RMDIR",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_RMDIR,
        args_children=(
            dirop3(name="NFS3-RMDIR_object", handle_data=dir_handle, filename=dirname),
        ),
    )


def nfs3_rename(
    from_dir_handle: bytes = None,
    from_name: str = "oldname",
    to_dir_handle: bytes = None,
    to_name: str = "newname",
) -> Request:
    """
    NFSv3 RENAME procedure (procedure 14).

    Args:
        RENAME3args:
            dirop3 from - source directory + name
            dirop3 to - destination directory + name

    Renames a file or directory.
    """
    return rpc_call_request(
        name="NFS3-RENAME",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_RENAME,
        args_children=(
            dirop3(
                name="NFS3-RENAME_from", handle_data=from_dir_handle, filename=from_name
            ),
            dirop3(name="NFS3-RENAME_to", handle_data=to_dir_handle, filename=to_name),
        ),
    )


def nfs3_readlink(handle_data: bytes = None) -> Request:
    """
    NFSv3 READLINK procedure (procedure 5).

    Args:
        READLINK3args:
            fhandle3 symlink - symbolic link file handle

    Reads the target of a symbolic link.
    """
    return rpc_call_request(
        name="NFS3-READLINK",
        program=PROG_NFS,
        version=NFS_V3,
        procedure=NFSPROC3_READLINK,
        args_children=(
            fhandle3(name="NFS3-READLINK_symlink", handle_data=handle_data),
        ),
    )


# =============================================================================
# Convenience: Get all procedure requests for fuzzing
# =============================================================================


def get_all_nfs3_requests() -> list:
    """
    Get a list of all NFSv3 procedure requests for comprehensive fuzzing.

    Returns:
        List of Request objects for all implemented NFSv3 procedures.
    """
    return [
        nfs3_null(),
        nfs3_getattr(),
        nfs3_lookup(),
        nfs3_access(),
        nfs3_readlink(),
        nfs3_read(),
        nfs3_write(),
        nfs3_create(),
        nfs3_mkdir(),
        nfs3_remove(),
        nfs3_rmdir(),
        nfs3_rename(),
        nfs3_readdir(),
        nfs3_readdirplus(),
        nfs3_fsstat(),
        nfs3_fsinfo(),
        nfs3_pathconf(),
        nfs3_commit(),
    ]
