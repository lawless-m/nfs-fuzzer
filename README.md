# NFS Protocol Fuzzer for boofuzz

A boofuzz-based protocol fuzzer for NFS (Network File System) servers, targeting NFSv3 implementations.

## Overview

This fuzzer provides:
- **Sun RPC primitives** - Reusable building blocks for any Sun RPC-based protocol
- **NFSv3 procedure definitions** - All 22 NFSv3 procedures defined per RFC 1813
- **Example fuzzer script** - Ready-to-use CLI for fuzzing NFS servers

## Installation

```bash
pip install boofuzz
```

## Usage

```bash
# Basic usage - fuzz stateless procedures
python examples/nfs3.py -t 192.168.1.100

# Fuzz specific procedures
python examples/nfs3.py -t 192.168.1.100 --procedures NULL,GETATTR,LOOKUP

# Fuzz all procedures
python examples/nfs3.py -t 192.168.1.100 --all-procedures

# Test connectivity only
python examples/nfs3.py -t 192.168.1.100 --test-connection
```

## Test Targets

### nfs-ganesha (Recommended for testing)

```bash
# Docker
docker run --rm -p 2049:2049 -v /tmp/nfs:/export erichough/nfs-server

# Or install locally
sudo apt install nfs-ganesha nfs-ganesha-vfs
```

### Linux NFSD

```bash
sudo apt install nfs-kernel-server
echo "/tmp/nfs-test *(rw,sync,no_subtree_check)" | sudo tee -a /etc/exports
sudo exportfs -ra
sudo systemctl start nfs-server
```

### Building with AddressSanitizer

For memory bug detection, build targets with ASAN:

```bash
export CFLAGS="-fsanitize=address -g"
export LDFLAGS="-fsanitize=address"
# Then build from source
```

## Project Structure

```
nfs-fuzzer/
├── request_definitions/
│   ├── __init__.py      # Package exports
│   ├── sunrpc.py        # Sun RPC primitives (RFC 5531)
│   └── nfs3.py          # NFSv3 procedures (RFC 1813)
├── examples/
│   └── nfs3.py          # Example fuzzer with CLI
└── README.md
```

## Implemented Procedures

| Procedure | Number | Description |
|-----------|--------|-------------|
| NULL | 0 | Connectivity test |
| GETATTR | 1 | Get file attributes |
| LOOKUP | 3 | Look up filename |
| ACCESS | 4 | Check access permissions |
| READLINK | 5 | Read symbolic link |
| READ | 6 | Read file data |
| WRITE | 7 | Write file data |
| CREATE | 8 | Create file |
| MKDIR | 9 | Create directory |
| REMOVE | 12 | Remove file |
| RMDIR | 13 | Remove directory |
| RENAME | 14 | Rename file/directory |
| READDIR | 16 | Read directory entries |
| READDIRPLUS | 17 | Read directory with attributes |
| FSSTAT | 18 | Get filesystem statistics |
| FSINFO | 19 | Get filesystem info |
| PATHCONF | 20 | Get POSIX path config |
| COMMIT | 21 | Commit cached data |

## Fuzzing Targets

Key areas for mutation:
- **File handle length** - 0, 65, MAX_INT (bounds checking)
- **Filenames** - Long strings, null bytes, path traversal (`../`)
- **Offset/count fields** - Negative values, MAX_INT64 (integer overflow)
- **Record mark length** - Mismatch with actual data (framing bugs)
- **XID** - Reuse, max values (state confusion)

## References

- [RFC 1813 - NFS Version 3 Protocol](https://tools.ietf.org/html/rfc1813)
- [RFC 5531 - RPC: Remote Procedure Call Protocol](https://tools.ietf.org/html/rfc5531)
- [RFC 4506 - XDR: External Data Representation](https://tools.ietf.org/html/rfc4506)
- [boofuzz documentation](https://boofuzz.readthedocs.io/)

## Contributing

Format code with Black before committing:

```bash
pip install black
black request_definitions/ examples/
```

## Responsible Disclosure

If you find vulnerabilities:
- **nfs-ganesha**: security@nfs-ganesha.org
- **Linux NFSD**: security@kernel.org

## License

MIT
