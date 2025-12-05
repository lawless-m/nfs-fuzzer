"""
boofuzz request definitions for NFS and related protocols.

This package provides protocol definitions for fuzzing:
- Sun RPC (ONC RPC) - RFC 5531
- NFS Version 3 - RFC 1813
"""

from .sunrpc import (
    # Constants
    PROG_PORTMAP,
    PROG_NFS,
    PROG_MOUNT,
    PORT_PORTMAP,
    PORT_NFS,
    AUTH_NONE,
    AUTH_SYS,
    MSG_TYPE_CALL,
    MSG_TYPE_REPLY,
    RPC_VERSION,
    # Functions
    rpc_call_request,
    rpc_call_block,
    tcp_record_mark,
    auth_none,
    auth_sys_block,
    xdr_pad_length,
    xdr_padded_bytes,
)

from .nfs3 import (
    # Constants
    NFS_V3,
    NFSPROC3_NULL,
    NFSPROC3_GETATTR,
    NFSPROC3_LOOKUP,
    NFSPROC3_READ,
    NFSPROC3_WRITE,
    # Data types
    fhandle3,
    filename3,
    dirop3,
    # Procedures
    nfs3_null,
    nfs3_getattr,
    nfs3_lookup,
    nfs3_access,
    nfs3_readlink,
    nfs3_read,
    nfs3_write,
    nfs3_create,
    nfs3_mkdir,
    nfs3_remove,
    nfs3_rmdir,
    nfs3_rename,
    nfs3_readdir,
    nfs3_readdirplus,
    nfs3_fsstat,
    nfs3_fsinfo,
    nfs3_pathconf,
    nfs3_commit,
    get_all_nfs3_requests,
)

__all__ = [
    # Sun RPC
    "PROG_PORTMAP",
    "PROG_NFS",
    "PROG_MOUNT",
    "PORT_PORTMAP",
    "PORT_NFS",
    "AUTH_NONE",
    "AUTH_SYS",
    "MSG_TYPE_CALL",
    "MSG_TYPE_REPLY",
    "RPC_VERSION",
    "rpc_call_request",
    "rpc_call_block",
    "tcp_record_mark",
    "auth_none",
    "auth_sys_block",
    "xdr_pad_length",
    "xdr_padded_bytes",
    # NFS v3
    "NFS_V3",
    "NFSPROC3_NULL",
    "NFSPROC3_GETATTR",
    "NFSPROC3_LOOKUP",
    "NFSPROC3_READ",
    "NFSPROC3_WRITE",
    "fhandle3",
    "filename3",
    "dirop3",
    "nfs3_null",
    "nfs3_getattr",
    "nfs3_lookup",
    "nfs3_access",
    "nfs3_readlink",
    "nfs3_read",
    "nfs3_write",
    "nfs3_create",
    "nfs3_mkdir",
    "nfs3_remove",
    "nfs3_rmdir",
    "nfs3_rename",
    "nfs3_readdir",
    "nfs3_readdirplus",
    "nfs3_fsstat",
    "nfs3_fsinfo",
    "nfs3_pathconf",
    "nfs3_commit",
    "get_all_nfs3_requests",
]
