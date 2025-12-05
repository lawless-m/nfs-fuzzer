# NFS Fuzzer Test Environment Setup

Two-VM setup using QEMU for testing the boofuzz NFS fuzzer.

## Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│   Alpine (Fuzzer)   │         │  Debian (Target)    │
│                     │  TCP    │                     │
│  boofuzz + nfs3.py  │ ──────► │  nfs-ganesha        │
│                     │  :2049  │  (with ASAN)        │
└─────────────────────┘         └─────────────────────┘
```

- **Debian VM**: Runs the NFS server (nfs-ganesha) - the fuzzing target
- **Alpine VM**: Runs the fuzzer (boofuzz + our NFS definitions)

---

## Part 1: Debian VM (Target)

### 1.1 Install nfs-ganesha

```bash
# Update and install
sudo apt update
sudo apt install -y nfs-ganesha nfs-ganesha-vfs

# Or build from source with ASAN (recommended for bug detection)
# See section 1.3 below
```

### 1.2 Configure nfs-ganesha

Create/edit `/etc/ganesha/ganesha.conf`:

```conf
# Minimal config for fuzzing

NFS_CORE_PARAM {
    NFS_Protocols = 3;          # NFSv3 only (simpler)
    Bind_addr = 0.0.0.0;        # Listen on all interfaces
}

EXPORT {
    Export_Id = 1;
    Path = /srv/nfs/fuzz;
    Pseudo = /fuzz;
    Access_Type = RW;
    Squash = No_root_squash;    # Permissive for testing
    Sectype = sys,none;         # Allow AUTH_NONE and AUTH_SYS

    FSAL {
        Name = VFS;
    }

    CLIENT {
        Clients = *;            # Allow all clients
        Access_Type = RW;
    }
}

LOG {
    Default_Log_Level = EVENT;  # Or DEBUG for more detail

    COMPONENTS {
        NFS_V3 = DEBUG;         # Verbose NFSv3 logging
    }
}
```

### 1.3 Create export directory

```bash
sudo mkdir -p /srv/nfs/fuzz
sudo chmod 777 /srv/nfs/fuzz

# Create some test files
echo "test content" | sudo tee /srv/nfs/fuzz/testfile
sudo mkdir /srv/nfs/fuzz/testdir
```

### 1.4 (Optional) Build nfs-ganesha with AddressSanitizer

For memory bug detection:

```bash
# Install build dependencies
sudo apt install -y git cmake build-essential \
    libkrb5-dev libdbus-1-dev liburcu-dev \
    libnfsidmap-dev libcap-dev libblkid-dev

# Clone source
git clone --depth 1 https://github.com/nfs-ganesha/nfs-ganesha.git
cd nfs-ganesha
git submodule update --init

# Build with ASAN
mkdir build && cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
    -DUSE_FSAL_VFS=ON \
    -DUSE_DBUS=OFF

make -j$(nproc)

# Run from build directory
sudo ./MainNFSD/ganesha.nfsd -F -L /dev/stdout -f /etc/ganesha/ganesha.conf
```

### 1.5 Start nfs-ganesha

```bash
# Using system service
sudo systemctl start nfs-ganesha
sudo systemctl status nfs-ganesha

# Or run in foreground (better for monitoring)
sudo ganesha.nfsd -F -L /dev/stdout -f /etc/ganesha/ganesha.conf
```

### 1.6 Verify it's running

```bash
# Check port 2049 is listening
ss -tlnp | grep 2049

# Check exports
showmount -e localhost
```

### 1.7 Get Debian VM IP address

```bash
ip addr show
# Note the IP, e.g., 192.168.122.10
```

---

## Part 2: Alpine VM (Fuzzer)

### 2.1 Install Python and dependencies

```bash
# Update packages
apk update

# Install Python and pip
apk add python3 py3-pip git

# Install boofuzz
pip3 install boofuzz
```

### 2.2 Clone the fuzzer

```bash
# Clone the repository (or copy files)
git clone <your-repo-url> nfs-fuzzer
cd nfs-fuzzer

# Or if copying manually, ensure you have:
# - request_definitions/sunrpc.py
# - request_definitions/nfs3.py
# - request_definitions/__init__.py
# - examples/nfs3.py
```

### 2.3 Verify network connectivity

```bash
# Ping the Debian VM
ping -c 3 <debian-ip>

# Check NFS port is reachable
nc -zv <debian-ip> 2049
```

### 2.4 Test the fuzzer

```bash
cd nfs-fuzzer

# Test connection mode (doesn't actually send)
python3 examples/nfs3.py -t <debian-ip> --test-connection

# Should output:
# NFS v3 Fuzzer
# Target: <debian-ip>:2049
# Procedures: NULL, GETATTR, LOOKUP, ACCESS, FSSTAT, FSINFO, PATHCONF
# ...
# NULL packet (44 bytes): 80000028...
```

---

## Part 3: Running the Fuzzer

### 3.1 Basic fuzzing

On Alpine VM:

```bash
cd nfs-fuzzer

# Start fuzzing default (stateless) procedures
python3 examples/nfs3.py -t <debian-ip>
```

### 3.2 Monitor on Debian VM

In a separate terminal on Debian:

```bash
# Watch nfs-ganesha logs
sudo journalctl -fu nfs-ganesha

# Or if running in foreground, logs go to stdout

# Watch for crashes
dmesg -w | grep -i -E "segfault|ganesha"
```

### 3.3 Fuzzing options

```bash
# Fuzz specific procedures
python3 examples/nfs3.py -t <debian-ip> --procedures NULL,LOOKUP,GETATTR

# Fuzz all procedures
python3 examples/nfs3.py -t <debian-ip> --all-procedures

# Custom web UI port
python3 examples/nfs3.py -t <debian-ip> --web-port 8080

# Headless (no web UI)
python3 examples/nfs3.py -t <debian-ip> --no-web
```

### 3.4 Access web UI

If Alpine has a GUI or you can forward ports:

```
http://<alpine-ip>:26000
```

---

## Part 4: Analyzing Results

### 4.1 Results location

Results are stored in `boofuzz-results/` as SQLite databases:

```bash
ls -la boofuzz-results/
# run-2024-01-15_10-30-45.db
```

### 4.2 View results

```bash
# Using boofuzz CLI
boo open boofuzz-results/run-*.db
```

### 4.3 Query crashes

```python
import sqlite3
conn = sqlite3.connect('boofuzz-results/run-YYYY-MM-DD_HH-MM-SS.db')
cursor = conn.cursor()
cursor.execute("""
    SELECT name, type, timestamp
    FROM cases
    WHERE type LIKE '%fail%' OR type LIKE '%crash%'
""")
for row in cursor.fetchall():
    print(row)
```

---

## Network Configuration Notes

### If VMs can't see each other

Check QEMU network mode:
- **User mode (default)**: VMs can't communicate directly
- **Bridge mode**: VMs get IPs on host network, can communicate
- **Host-only**: VMs can communicate with each other and host

For bridge networking in QEMU:
```bash
# On host, create bridge
sudo ip link add br0 type bridge
sudo ip link set br0 up

# Start VM with bridge
qemu-system-x86_64 ... -netdev bridge,id=net0,br=br0 -device virtio-net,netdev=net0
```

### Firewall

On Debian, ensure port 2049 is open:
```bash
sudo ufw allow 2049/tcp
# or
sudo iptables -A INPUT -p tcp --dport 2049 -j ACCEPT
```

---

## Quick Reference

| VM | Role | Key Software | Port |
|----|------|--------------|------|
| Debian | Target | nfs-ganesha | 2049 |
| Alpine | Fuzzer | boofuzz, Python | 26000 (web UI) |

### Commands Summary

**Debian (Target):**
```bash
sudo systemctl start nfs-ganesha    # Start NFS server
sudo journalctl -fu nfs-ganesha     # Watch logs
ss -tlnp | grep 2049                # Verify listening
```

**Alpine (Fuzzer):**
```bash
python3 examples/nfs3.py -t <debian-ip>                    # Start fuzzing
python3 examples/nfs3.py -t <debian-ip> --test-connection  # Test only
python3 examples/nfs3.py -t <debian-ip> --all-procedures   # Fuzz everything
```
