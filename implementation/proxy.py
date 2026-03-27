import socket
import threading
import logging

logging.basicConfig(filename="proxy.log", filemode='a', format = '%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 1102   

FAKE_SERIAL = b"S C-C9XY12345678"
FAKE_ASNAME = b"SIMATIC-300"

MODULE_TYPE_LEN = 33
SERIAL_LEN = 25
ASNAME_LEN = 25

def is_cpu_info_response(packet):
    if len(packet) < 100:
        return False
    if packet[0] != 0x03:
        return False
    if b"SNAP7-SERVER" in packet or b"S C-C2UR" in packet:
        return True
    return False

def rewrite_cpu_info(packet):
    modified = bytearray(packet)

    serial_idx = packet.find(b"S C-C2UR")
    if serial_idx != -1:
        fake = FAKE_SERIAL.ljust(25, b"\x00")
        modified[serial_idx:serial_idx+25] = fake
        logging.info(f"Rewrote serial at offset {serial_idx}")
    else:
        logging.info("Serial not found")

    asname_idx = packet.find(b"SNAP7-SERVER")
    if asname_idx != -1:
        fake = FAKE_ASNAME.ljust(25, b"\x00")
        modified[asname_idx:asname_idx+25] = fake
        logging.info(f"Rewrote ASName at offset {asname_idx}")
    else:
        logging.info("ASName not found")

    return bytes(modified)

def forward_client_to_plc(client_sock, plc_sock):
    while True:
        try:
            data = client_sock.recv(4096)
            if not data:
                logging.info("[C→P] connection closed")
                break
            logging.info(f"[C→P] {len(data)}b: {data.hex()}")
            plc_sock.sendall(data)
        except Exception as e:                          
            logging.info(f"[C→P ERROR] {e}")
            break

def forward_plc_to_client(plc_sock, client_sock):
    while True:
        try:
            data = plc_sock.recv(4096)
            if not data:
                logging.info("[P→C] connection closed")
                break
            logging.info(f"[P→C] {len(data)}b: {data.hex()}") 
            if is_cpu_info_response(data):
                logging.info("Intercepted CPU Info response")
                data = rewrite_cpu_info(data)
            client_sock.sendall(data)
        except Exception as e:                          
            logging.info(f"[P→C ERROR] {e}")
            break

def handle_client(client_socket):
    first = client_socket.recv(4)      
    if len(first) < 4 or first[0] != 0x03:
        client_socket.close()
        return

    plc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    plc_socket.connect((TARGET_HOST, TARGET_PORT))
    plc_socket.sendall(first)          

    t1 = threading.Thread(target=forward_client_to_plc, args=(client_socket, plc_socket))
    t2 = threading.Thread(target=forward_plc_to_client, args=(plc_socket, client_socket))
    t1.daemon = True
    t2.daemon = True
    t1.start()
    t2.start()
    t1.join()                           
    t2.join()


def start_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 102))
    server.listen(5)

    logging.info("CPU Info Proxy listening on port 102")
    logging.info(f"Forwarding to Snap7 on port {TARGET_PORT}")

    while True:
        client_sock, addr = server.accept()
        logging.info(f"Connection from {addr}")
        threading.Thread(target=handle_client, args=(client_sock,)).start()


if __name__ == "__main__":
    start_proxy()
