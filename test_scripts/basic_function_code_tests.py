import snap7
import struct

PLC_IP = "127.0.0.1"
client = snap7.client.Client()

def connect():
    print("Connecting to PLC")
    client.connect(PLC_IP, 0, 0)
    if client.get_connected():
        print("Connected to PLC")
    else:
        raise RuntimeError("Connection failed")

def diagnostics():
    try:
        info = client.get_cpu_info()
        print("CPU Info:", info)
    except Exception as e:
        print("Diagnostics failed:", e)

def read_test():
    print("Testing read DB1.DBD800")
    try:
        data = client.read_area(snap7.Area.MK, 1, 0, 1)
        value = struct.unpack('>f', data)[0]
        print("Read DB800 value =", value)
        print("Read Successful")
    except Exception as e:
        print("Read failed:", e)

def write_test():
    print("Testing write (0x05)")
    try:
        value = (1234).to_bytes(4, 'big')
        client.db_write(1, 0, value)
        print("Write successful")
    except Exception as e:
        print("Write failed:", e)

def download_test():
    print("Testing download")
    try:
        data = client.upload(snap7.SrvArea.DB)
        print(f"Uploaded {len(data)} bytes from DB1")
        client.download(data, 1)
        print("Download complete")
    except Exception as e:
        print("Download failed:", e)

def upload_test():
    print("Testing upload")
    try:
        data = client.upload(3)
        print(f"Upload complete, got {len(data)} bytes")
    except Exception as e:
        print("Upload failed:", e)

def plc_stop():
    print("Testing PLC Stop")
    try:
        client.plc_stop()
        print("PLC Stop sent")
    except Exception as e:
        print("PLC Stop failed: ", e)

def directory():
    print("Directory test")
    try:
        data = client.list_blocks()
        print(data)
    except Exception as e:
        print("Failed:", e)

def main():
    connect()
    tests = {
        0x00: ("diagnostics", diagnostics),
        0x04: ("read", read_test),
        0x05: ("write", write_test),
        0x1B: ("download_block", download_test),
        0x1E: ("upload", upload_test),
        0x29: ("plc_stop", plc_stop),
        0x40: ("directory", directory),
    }

    for fc, (name, func) in tests.items():
        print("\n")
        print(f"Testing FC {hex(fc)}: {name}")
        func()

    client.disconnect()
    print("Disconnected")

if __name__ == "__main__":
    main()