"""Minidump header parser — extracts bugcheck & exception info without WinDbg."""

import struct
import sys
import os
from datetime import datetime

def parse_minidump(dmp_path: str) -> dict:
    with open(dmp_path, 'rb') as f:
        sig = f.read(4)
        if sig != b'MDMP':
            return {'error': f'Not a minidump file: {sig}'}

        ver = struct.unpack('<H', f.read(2))[0]
        impl = struct.unpack('<H', f.read(2))[0]
        nstreams = struct.unpack('<I', f.read(4))[0]
        stream_rva = struct.unpack('<I', f.read(4))[0]
        checksum = struct.unpack('<I', f.read(4))[0]
        timestamp = struct.unpack('<I', f.read(4))[0]
        flags = struct.unpack('<Q', f.read(8))[0]

        # Read stream directory
        streams = {}
        for i in range(nstreams):
            f.seek(stream_rva + i * 12)
            stype = struct.unpack('<I', f.read(4))[0]
            ssize = struct.unpack('<I', f.read(4))[0]
            sloc = struct.unpack('<I', f.read(4))[0]
            streams[stype] = (sloc, ssize)

        result = {
            'version': f'0x{ver:04x}',
            'streams': nstreams,
            'timestamp': timestamp,
            'crash_time': datetime.fromtimestamp(timestamp).isoformat(),
        }

        # Exception stream (type 6)
        if 6 in streams:
            loc, size = streams[6]
            f.seek(loc)
            thread_id = struct.unpack('<I', f.read(4))[0]
            f.read(4)
            exc_code = struct.unpack('<I', f.read(4))[0]
            exc_flags = struct.unpack('<I', f.read(4))[0]
            f.read(8)  # exception record ptr
            exc_addr = struct.unpack('<Q', f.read(8))[0]
            nparams = struct.unpack('<I', f.read(4))[0]
            params = [struct.unpack('<Q', f.read(8))[0] for _ in range(min(nparams, 15))]

            result['exception'] = {
                'thread_id': thread_id,
                'code': f'0x{exc_code:08x}',
                'flags': f'0x{exc_flags:08x}',
                'address': f'0x{exc_addr:016x}',
                'num_params': nparams,
                'params': [f'0x{p:016x}' for p in params],
            }
            result['bugcheck_code'] = f'0x{exc_code:08x}'

        # Module list stream (type 4) — get faulting module
        if 4 in streams:
            loc, size = streams[4]
            f.seek(loc)
            nmodules = struct.unpack('<I', f.read(4))[0]
            modules = []
            for i in range(min(nmodules, 50)):
                base = struct.unpack('<Q', f.read(8))[0]
                msize = struct.unpack('<I', f.read(4))[0]
                f.read(4)
                checksum = struct.unpack('<I', f.read(4))[0]
                timestamp = struct.unpack('<I', f.read(4))[0]
                name_rva = struct.unpack('<I', f.read(4))[0]
                # Simplified: read module name
                cur = f.tell()
                f.seek(loc + 4 + nmodules * 108 + name_rva - 4)
                name = b''
                for _ in range(128):
                    b = f.read(1)
                    if b == b'\x00':
                        break
                    name += b
                f.seek(cur)
                modules.append({
                    'base': f'0x{base:016x}',
                    'size': msize,
                    'name': name.decode('utf-8', errors='replace'),
                })
            # Save only top 10
            result['modules'] = modules[:20]

        # System info stream (type 7)
        if 7 in streams:
            loc, size = streams[7]
            f.seek(loc)
            proc_arch = struct.unpack('<H', f.read(2))[0]
            proc_level = struct.unpack('<H', f.read(2))[0]
            proc_rev = struct.unpack('<H', f.read(2))[0]
            f.read(2)  # reserved
            nproc = struct.unpack('<B', f.read(1))[0]
            prod_type = struct.unpack('<B', f.read(1))[0]
            major = struct.unpack('<I', f.read(4))[0]
            minor = struct.unpack('<I', f.read(4))[0]
            build = struct.unpack('<I', f.read(4))[0]
            platform = struct.unpack('<I', f.read(4))[0]
            result['system'] = {
                'proc_arch': proc_arch,
                'os_version': f'{major}.{minor}.{build}',
                'num_processors': nproc,
            }

        return result


KNOWN_BUGCHECKS = {
    0x0000001a: 'MEMORY_MANAGEMENT',
    0x0000001e: 'KMODE_EXCEPTION_NOT_HANDLED',
    0x0000003b: 'SYSTEM_SERVICE_EXCEPTION',
    0x00000050: 'PAGE_FAULT_IN_NONPAGED_AREA',
    0x0000007e: 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED',
    0x000000c1: 'SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION',
    0x000000c4: 'DRIVER_VERIFIER_DETECTED_VIOLATION',
    0x000000d1: 'DRIVER_IRQL_NOT_LESS_OR_EQUAL',
    0x000000ef: 'CRITICAL_PROCESS_DIED',
    0x00000101: 'CLOCK_WATCHDOG_TIMEOUT',
    0x00000109: 'CRITICAL_STRUCTURE_CORRUPTION',
    0x00000124: 'WHEA_UNCORRECTABLE_ERROR',
    0x00000133: 'DPC_WATCHDOG_VIOLATION',
    0x00000139: 'KERNEL_SECURITY_CHECK_FAILURE',
    0x00000154: 'UNEXPECTED_STORE_EXCEPTION',
    0x000001aa: 'EXCEPTION_ON_INVALID_STACK',
    0x000001c6: 'FAST_ERESOURCE_PRECONDITION_VIOLATION',
    0x000001c7: 'STORE_DATA_STRUCTURE_CORRUPTION',
}


def main():
    dmp = sys.argv[1] if len(sys.argv) > 1 else r'C:\Windows\Minidump\070826-14875-01.dmp'
    result = parse_minidump(dmp)

    print(f"Crash Time: {result.get('crash_time')}")
    print(f"Dump Version: {result.get('version')}, {result.get('streams')} streams")

    if 'system' in result:
        s = result['system']
        print(f"OS: {s['os_version']}, CPUs: {s['num_processors']}")

    if 'bugcheck_code' in result:
        code = result['bugcheck_code']
        code_int = int(code, 16)
        name = KNOWN_BUGCHECKS.get(code_int, 'UNKNOWN')
        print(f"\nBugcheck: {code} — {name}")

    if 'exception' in result:
        e = result['exception']
        print(f"\nException Record:")
        print(f"  Code: {e['code']}")
        print(f"  Address: {e['address']}")
        print(f"  ThreadId: {e['thread_id']}")
        for j, p in enumerate(e['params']):
            print(f"  Param[{j}]: {p}")

    if 'modules' in result:
        print(f"\nLoaded Modules (top 20):")
        for m in result['modules']:
            print(f"  {m['base']} {m['name']} ({m['size']} bytes)")


if __name__ == '__main__':
    main()
