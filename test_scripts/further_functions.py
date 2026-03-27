import snap7
import struct
import argparse
import time

parser = argparse.ArgumentParser(description="Probe a conpot S7 honeypot")
parser.add_argument("--host", default="127.0.0.1")
args = parser.parse_args()

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
WARN = "\033[93mWARN\033[0m"

results = []

def run(name, fn):
    try:
        result = fn()
        print(f"  [{PASS}] {name}")
        if result is not None:
            print(f"          → {result}")
        results.append((name, "PASS", result))
    except Exception as e:
        print(f"  [{FAIL}] {name}: {e}")
        results.append((name, "FAIL", str(e)))

# Connect
print(f"  CONPOT S7 HONEYPOT PROBE")
print(f"  Target: {args.host}:{args.port}")

client = snap7.client.Client()

print("0. Connecting")
try:
    client.connect(args.host, 0, 1, 102)
    print(f"  [{PASS}] Connected to {args.host}:102")
except Exception as e:
    print(f"  [{FAIL}] Could not connect: {e}")
    exit(1)

# CPU Info
print("\n1. CPU identification")

def test_cpu_info():
    info = client.get_cpu_info()
    return {
        "module_type": info.ModuleTypeName.decode().strip('\x00'),
        "serial":      info.SerialNumber.decode().strip('\x00'),
        "as_name":     info.ASName.decode().strip('\x00'),
        "module_name": info.ModuleName.decode().strip('\x00'),
        "copyright":   info.Copyright.decode().strip('\x00'),
    }

def test_cpu_state():
    state = client.get_cpu_state()
    states = {0: "UNKNOWN", 4: "STOP", 8: "RUN"}
    return states.get(state, f"RAW={state}")


run("get_cpu_info()",   test_cpu_info)
run("get_cpu_state()",  test_cpu_state)

# 2. DB reads 

print("\n2. DB area reads")

DB_PROBES = [
    (1, 0,   4,  "DB1 offset 0   (DB800 float)"),
    (1, 4,   4,  "DB1 offset 4   (DB801 float)"),
    (1, 8,   4,  "DB1 offset 8   (DB802 float)"),
    (1, 0,   16, "DB1 offset 0   (4 floats)"),
    (1, 392, 4,  "DB1 offset 392 (DB898 float)"),
]

for db_num, offset, length, label in DB_PROBES:
    def make_db_read(n, o, l):
        def fn():
            data = client.read_area(snap7.Area.DB, n, o, l)
            floats = [struct.unpack('>f', data[i:i+4])[0] for i in range(0, len(data), 4)]
            return [round(f, 3) for f in floats]
        return fn
    run(f"DB read: {label}", make_db_read(db_num, offset, length))

# 3. Merker (MK) reads

print("\n3. Merker (MK) area reads")

MK_PROBES = [
    (0, 1, "MK byte 0"),
    (0, 8, "MK bytes 0-7"),
]

for offset, length, label in MK_PROBES:
    def make_mk_read(o, l):
        def fn():
            data = client.read_area(snap7.Area.MK, 0, o, l)
            return list(data)
        return fn
    run(f"MK read: {label}", make_mk_read(offset, length))

# 4. Input (PE) reads

print("\n4. Input (PE) area reads")

def test_pe_read():
    data = client.read_area(snap7.Area.PE, 0, 0, 1)
    return list(data)

run("PE read: byte 0", test_pe_read)

# 5. Output (PA) reads

print("\n5. Output (PA) area reads")

PA_PROBES = [
    (0, 1,  "PA byte 0"),
    (0, 8,  "PA bytes 0-7"),
    (0, 16, "PA bytes 0-15"),
]

for offset, length, label in PA_PROBES:
    def make_pa_read(o, l):
        def fn():
            data = client.read_area(snap7.Area.PA, 0, o, l)
            return list(data)
        return fn
    run(f"PA read: {label}", make_pa_read(offset, length))

# 6. Write attempts

print("\n6. Write probes (honeypot should accept or silently drop)")

def test_db_write():
    payload = struct.pack('>f', 42.0)
    client.write_area(snap7.Area.DB, 1, 0, payload)
    return "write accepted"

def test_db_write_verify():
    # Write a known value then read it back
    payload = struct.pack('>f', 99.9)
    client.write_area(snap7.Area.DB, 1, 0, payload)
    time.sleep(0.1)
    data = client.read_area(snap7.Area.PE, 1, 0, 4)
    readback = round(struct.unpack('>f', data)[0], 2)
    return f"wrote 99.9, read back {readback} ({'matches' if readback == 99.9 else 'does NOT match — honeypot ignoring writes'})"

def test_mk_write():
    client.write_area(snap7.Area.MK, 0, 0, bytes([0xFF]))
    return "write accepted"

def test_pa_write():
    client.write_area(snap7.Area.PA, 0, 0, bytes([0xFF]))
    return "write accepted"

def test_pe_write():
    client.write_area(snap7.Area.PE, 0, 0, bytes([0xFF]))
    return "write accepted"

run("DB write",                test_db_write)
run("DB write + readback",     test_db_write_verify)
run("MK write",                test_mk_write)
run("PA write",                test_db_write)
run("PE write",                test_pe_write)


print("\n7. Refresh behaviour")

def test_db_refreshes():
    values = []
    for _ in range(3): 
        data = client.read_area(snap7.Area.DB, 1, 0, 4)
        # data = client.read_area(snap7.Area.MK, 0, 0, 1)
        values.append(round(struct.unpack('>f', data)[0], 3))
        # values.append(data[0])
        time.sleep(10)
    unique = len(set(values))
    return f"readings: {values} — {'refreshing' if unique > 1 else 'NOT refreshing'}"

run("DB refreshes on repeated reads", test_db_refreshes)

# Summary

client.disconnect()

print(f"  SUMMARY")
passed  = sum(1 for _, s, _ in results if s == "PASS")
failed  = sum(1 for _, s, _ in results if s == "FAIL")
total   = len(results)
print(f"  Total: {total}  |  {PASS}: {passed}  |  {FAIL}: {failed}")

if failed:
    print(f"\n  Failed probes:")
    for name, status, err in results:
        if status == "FAIL":
            print(f"    • {name}: {err}")
print()