"""
Sun RPC (ONC RPC) Protocol Definitions for boofuzz

RFC 5531 - Remote Procedure Call Protocol Version 2
RFC 4506 - XDR: External Data Representation Standard

This module provides reusable building blocks for fuzzing Sun RPC-based
protocols including NFS, NIS, and others.
"""

from boofuzz import (
    Block,
    Bytes,
    DWord,
    Request,
    Size,
    Static,
    String,
    BIG_ENDIAN,
)

# =============================================================================
# Constants (RFC 5531)
# =============================================================================

# RPC Message Types
MSG_TYPE_CALL = 0
MSG_TYPE_REPLY = 1

# RPC Version
RPC_VERSION = 2

# Program Numbers
PROG_PORTMAP = 100000
PROG_NFS = 100003
PROG_MOUNT = 100005

# Authentication Flavors
AUTH_NONE = 0
AUTH_SYS = 1  # Unix-style (UID/GID)
AUTH_SHORT = 2
AUTH_DES = 3
RPCSEC_GSS = 6

# Standard Ports
PORT_PORTMAP = 111
PORT_NFS = 2049


# =============================================================================
# XDR Padding Helper
# =============================================================================


def xdr_pad_length(length: int) -> int:
    """Calculate padding needed to align to 4-byte XDR boundary."""
    return (4 - (length % 4)) % 4


def xdr_padded_bytes(data: bytes) -> bytes:
    """Return data padded to 4-byte XDR boundary."""
    pad = xdr_pad_length(len(data))
    return data + (b"\x00" * pad)


# =============================================================================
# TCP Record Marking
# =============================================================================


def tcp_record_mark(block_name: str, name: str = "record_mark") -> Size:
    """
    Create TCP record marking header for RPC over TCP.

    The record mark is a 4-byte header where:
    - Bit 31: Last fragment flag (1 = last/only fragment)
    - Bits 0-30: Fragment length (excludes the 4-byte header itself)

    Args:
        block_name: Name of the block whose size to calculate
        name: Name for this size field

    Returns:
        Size primitive configured for TCP record marking
    """
    return Size(
        name=name,
        block_name=block_name,
        length=4,
        endian=BIG_ENDIAN,
        math=lambda x: 0x80000000 | x,  # Set last fragment bit
        fuzzable=True,
    )


# =============================================================================
# Authentication Primitives
# =============================================================================


def auth_none(name_prefix: str = "auth") -> tuple:
    """
    Create AUTH_NONE credentials (no authentication).

    Returns tuple of (credentials_block, verifier_block) children.
    """
    return (
        # Credentials
        DWord(
            name=f"{name_prefix}_cred_flavor",
            default_value=AUTH_NONE,
            endian=BIG_ENDIAN,
        ),
        DWord(name=f"{name_prefix}_cred_length", default_value=0, endian=BIG_ENDIAN),
        # Verifier
        DWord(
            name=f"{name_prefix}_verf_flavor",
            default_value=AUTH_NONE,
            endian=BIG_ENDIAN,
        ),
        DWord(name=f"{name_prefix}_verf_length", default_value=0, endian=BIG_ENDIAN),
    )


def auth_sys_block(
    name: str = "auth_sys",
    machine_name: str = "fuzzer",
    uid: int = 0,
    gid: int = 0,
) -> Block:
    """
    Create AUTH_SYS (Unix-style) credentials block.

    AUTH_SYS contains:
    - stamp (4 bytes, arbitrary)
    - machine name (XDR string)
    - uid (4 bytes)
    - gid (4 bytes)
    - auxiliary gids (XDR array, we use empty)

    Args:
        name: Block name
        machine_name: Machine name string
        uid: User ID
        gid: Group ID

    Returns:
        Block containing AUTH_SYS credentials
    """
    # Calculate padded machine name for proper XDR encoding
    name_bytes = machine_name.encode("utf-8")
    name_padded_len = len(name_bytes) + xdr_pad_length(len(name_bytes))

    return Block(
        name=name,
        children=(
            # Credentials flavor and length
            DWord(
                name=f"{name}_cred_flavor", default_value=AUTH_SYS, endian=BIG_ENDIAN
            ),
            Size(
                name=f"{name}_cred_length",
                block_name=f"{name}_cred_body",
                length=4,
                endian=BIG_ENDIAN,
            ),
            # Credentials body
            Block(
                name=f"{name}_cred_body",
                children=(
                    DWord(name=f"{name}_stamp", default_value=0, endian=BIG_ENDIAN),
                    # Machine name as XDR string (length + data + padding)
                    DWord(
                        name=f"{name}_machine_len",
                        default_value=len(name_bytes),
                        endian=BIG_ENDIAN,
                    ),
                    Static(
                        name=f"{name}_machine",
                        default_value=xdr_padded_bytes(name_bytes),
                    ),
                    DWord(
                        name=f"{name}_uid",
                        default_value=uid,
                        endian=BIG_ENDIAN,
                        fuzzable=True,
                    ),
                    DWord(
                        name=f"{name}_gid",
                        default_value=gid,
                        endian=BIG_ENDIAN,
                        fuzzable=True,
                    ),
                    # Auxiliary GIDs (empty array)
                    DWord(
                        name=f"{name}_aux_gid_count", default_value=0, endian=BIG_ENDIAN
                    ),
                ),
            ),
            # Verifier (AUTH_NONE)
            DWord(
                name=f"{name}_verf_flavor", default_value=AUTH_NONE, endian=BIG_ENDIAN
            ),
            DWord(name=f"{name}_verf_length", default_value=0, endian=BIG_ENDIAN),
        ),
    )


# =============================================================================
# RPC Call Message Builder
# =============================================================================


def rpc_call_request(
    name: str,
    program: int,
    version: int,
    procedure: int,
    args_children: tuple = (),
    auth_type: str = "none",
    xid: int = 0x00000001,
) -> Request:
    """
    Create a complete RPC CALL request with TCP record marking.

    This builds the full message structure:
    - TCP record mark (4 bytes)
    - RPC header (XID, msg type, RPC version, program, version, procedure)
    - Authentication (credentials + verifier)
    - Procedure-specific arguments

    Args:
        name: Request name (e.g., "NFS-NULL", "NFS-GETATTR")
        program: RPC program number (e.g., PROG_NFS = 100003)
        version: Program version (e.g., 3 for NFSv3)
        procedure: Procedure number
        args_children: Tuple of children for procedure arguments
        auth_type: Authentication type ("none" or "sys")
        xid: Transaction ID

    Returns:
        Complete Request object ready for fuzzing
    """
    # Build auth block based on type
    if auth_type == "sys":
        auth_children = (auth_sys_block(name=f"{name}_auth"),)
    else:
        auth_children = auth_none(name_prefix=f"{name}_auth")

    return Request(
        name=name,
        children=(
            # TCP Record Mark - sizes the rpc_message block
            tcp_record_mark(
                block_name=f"{name}_rpc_message", name=f"{name}_record_mark"
            ),
            # RPC Message body
            Block(
                name=f"{name}_rpc_message",
                children=(
                    # RPC Header
                    DWord(
                        name=f"{name}_xid",
                        default_value=xid,
                        endian=BIG_ENDIAN,
                        fuzzable=True,
                    ),
                    DWord(
                        name=f"{name}_msg_type",
                        default_value=MSG_TYPE_CALL,
                        endian=BIG_ENDIAN,
                        fuzzable=True,
                    ),
                    DWord(
                        name=f"{name}_rpc_version",
                        default_value=RPC_VERSION,
                        endian=BIG_ENDIAN,
                        fuzzable=True,
                    ),
                    DWord(
                        name=f"{name}_program",
                        default_value=program,
                        endian=BIG_ENDIAN,
                        fuzzable=True,
                    ),
                    DWord(
                        name=f"{name}_version",
                        default_value=version,
                        endian=BIG_ENDIAN,
                        fuzzable=True,
                    ),
                    DWord(
                        name=f"{name}_procedure",
                        default_value=procedure,
                        endian=BIG_ENDIAN,
                        fuzzable=True,
                    ),
                    # Authentication
                    *auth_children,
                    # Procedure arguments
                    *args_children,
                ),
            ),
        ),
    )


def rpc_call_block(
    name: str,
    program: int,
    version: int,
    procedure: int,
    args_children: tuple = (),
    auth_type: str = "none",
    xid: int = 0x00000001,
) -> tuple:
    """
    Create RPC CALL components as a tuple of children (for embedding in Request).

    Similar to rpc_call_request but returns children tuple instead of Request.
    Useful when building compound messages or custom request structures.

    Args:
        name: Name prefix for all fields
        program: RPC program number
        version: Program version
        procedure: Procedure number
        args_children: Tuple of children for procedure arguments
        auth_type: Authentication type ("none" or "sys")
        xid: Transaction ID

    Returns:
        Tuple of children for embedding in a Request
    """
    if auth_type == "sys":
        auth_children = (auth_sys_block(name=f"{name}_auth"),)
    else:
        auth_children = auth_none(name_prefix=f"{name}_auth")

    return (
        tcp_record_mark(block_name=f"{name}_rpc_message", name=f"{name}_record_mark"),
        Block(
            name=f"{name}_rpc_message",
            children=(
                DWord(
                    name=f"{name}_xid",
                    default_value=xid,
                    endian=BIG_ENDIAN,
                    fuzzable=True,
                ),
                DWord(
                    name=f"{name}_msg_type",
                    default_value=MSG_TYPE_CALL,
                    endian=BIG_ENDIAN,
                    fuzzable=True,
                ),
                DWord(
                    name=f"{name}_rpc_version",
                    default_value=RPC_VERSION,
                    endian=BIG_ENDIAN,
                    fuzzable=True,
                ),
                DWord(
                    name=f"{name}_program",
                    default_value=program,
                    endian=BIG_ENDIAN,
                    fuzzable=True,
                ),
                DWord(
                    name=f"{name}_version",
                    default_value=version,
                    endian=BIG_ENDIAN,
                    fuzzable=True,
                ),
                DWord(
                    name=f"{name}_procedure",
                    default_value=procedure,
                    endian=BIG_ENDIAN,
                    fuzzable=True,
                ),
                *auth_children,
                *args_children,
            ),
        ),
    )
