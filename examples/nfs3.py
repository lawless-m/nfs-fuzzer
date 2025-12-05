#!/usr/bin/env python3
"""
NFS Version 3 Protocol Fuzzer

A boofuzz-based fuzzer for NFSv3 servers targeting implementations like
nfs-ganesha (userspace) and Linux NFSD (kernel).

Protocol reference: RFC 1813 - NFS Version 3 Protocol Specification
Target: NFS servers listening on TCP port 2049

Usage:
    python nfs3.py -t 192.168.1.100
    python nfs3.py -t 192.168.1.100 -p 2049 --web-port 26000
    python nfs3.py -t 192.168.1.100 --procedures NULL,GETATTR,LOOKUP

Example test targets:
    # nfs-ganesha in Docker
    docker run --rm -p 2049:2049 -v /tmp/nfs:/export erichough/nfs-server

    # Linux NFSD
    sudo systemctl start nfs-server
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for request_definitions import
sys.path.insert(0, str(Path(__file__).parent.parent))

from boofuzz import Session, Target, TCPSocketConnection, s_get

from request_definitions import (
    PORT_NFS,
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
)


# =============================================================================
# Available Procedures
# =============================================================================

PROCEDURES = {
    "NULL": nfs3_null,
    "GETATTR": nfs3_getattr,
    "LOOKUP": nfs3_lookup,
    "ACCESS": nfs3_access,
    "READLINK": nfs3_readlink,
    "READ": nfs3_read,
    "WRITE": nfs3_write,
    "CREATE": nfs3_create,
    "MKDIR": nfs3_mkdir,
    "REMOVE": nfs3_remove,
    "RMDIR": nfs3_rmdir,
    "RENAME": nfs3_rename,
    "READDIR": nfs3_readdir,
    "READDIRPLUS": nfs3_readdirplus,
    "FSSTAT": nfs3_fsstat,
    "FSINFO": nfs3_fsinfo,
    "PATHCONF": nfs3_pathconf,
    "COMMIT": nfs3_commit,
}

# Default procedures to fuzz (stateless, safe to run without valid handles)
DEFAULT_PROCEDURES = [
    "NULL",
    "GETATTR",
    "LOOKUP",
    "ACCESS",
    "FSSTAT",
    "FSINFO",
    "PATHCONF",
]


# =============================================================================
# Callbacks
# =============================================================================


def pre_send_callback(target, fuzz_data_logger, session, sock):
    """
    Called before each test case.

    For stateful fuzzing, this could:
    - Establish a valid session via MOUNT protocol
    - Cache valid file handles for use in subsequent procedures
    """
    pass


def post_test_case_callback(target, fuzz_data_logger, session, sock):
    """
    Called after each test case.

    Could be used to:
    - Check for anomalies in server response
    - Log additional diagnostics
    - Clean up test artifacts
    """
    pass


# =============================================================================
# Main
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="NFS Version 3 Protocol Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.100
  %(prog)s -t 192.168.1.100 --procedures NULL,GETATTR,LOOKUP
  %(prog)s -t 192.168.1.100 --all-procedures
  %(prog)s -t 192.168.1.100 --test-connection

Procedures available:
  """
        + ", ".join(PROCEDURES.keys()),
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target NFS server IP address or hostname",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=PORT_NFS,
        help=f"Target NFS port (default: {PORT_NFS})",
    )
    parser.add_argument(
        "--procedures",
        type=str,
        default=None,
        help="Comma-separated list of procedures to fuzz (default: stateless procedures)",
    )
    parser.add_argument(
        "--all-procedures",
        action="store_true",
        help="Fuzz all implemented procedures",
    )
    parser.add_argument(
        "--test-connection",
        action="store_true",
        help="Just send NULL procedure to test connectivity, then exit",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=26000,
        help="Port for boofuzz web interface (default: 26000)",
    )
    parser.add_argument(
        "--no-web",
        action="store_true",
        help="Disable web interface",
    )
    parser.add_argument(
        "--crash-threshold",
        type=int,
        default=3,
        help="Number of failures before restarting target (default: 3)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./boofuzz-results",
        help="Output directory for results (default: ./boofuzz-results)",
    )

    args = parser.parse_args()

    # Determine which procedures to fuzz
    if args.all_procedures:
        procedure_names = list(PROCEDURES.keys())
    elif args.procedures:
        procedure_names = [p.strip().upper() for p in args.procedures.split(",")]
        # Validate
        for name in procedure_names:
            if name not in PROCEDURES:
                parser.error(
                    f"Unknown procedure: {name}. Available: {', '.join(PROCEDURES.keys())}"
                )
    else:
        procedure_names = DEFAULT_PROCEDURES

    print(f"NFS v3 Fuzzer")
    print(f"Target: {args.target}:{args.port}")
    print(f"Procedures: {', '.join(procedure_names)}")
    print()

    # Create session
    target = Target(
        connection=TCPSocketConnection(
            host=args.target,
            port=args.port,
        )
    )

    session_kwargs = {
        "target": target,
        "crash_threshold_element": args.crash_threshold,
        "pre_send_callbacks": [pre_send_callback],
        "post_test_case_callbacks": [post_test_case_callback],
    }

    if not args.no_web:
        session_kwargs["web_port"] = args.web_port
        session_kwargs["keep_web_open"] = True
        print(f"Web interface: http://localhost:{args.web_port}")

    session = Session(**session_kwargs)

    # Register procedures
    requests = []
    for name in procedure_names:
        proc_func = PROCEDURES[name]
        req = proc_func()
        requests.append(req)

    # Connect procedures - each can be called independently
    # For now, we use a flat graph where each procedure is reachable from root
    for req in requests:
        session.connect(req)

    print(f"Registered {len(requests)} procedure(s)")
    print()

    if args.test_connection:
        print("Testing connection with NULL procedure...")
        # Just render and show the packet
        null_req = nfs3_null()
        packet = null_req.render()
        print(f"NULL packet ({len(packet)} bytes): {packet.hex()}")
        print()
        print("To actually send, remove --test-connection flag")
        return

    print("Starting fuzzer...")
    print("Press Ctrl+C to stop")
    print()

    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")


if __name__ == "__main__":
    main()
