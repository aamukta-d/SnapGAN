import snap7
from snap7 import SrvArea
from sdv.utils import load_synthesizer
from sdv.sampling import Condition
import pandas as pd
import time, logging, ctypes, struct

logging.basicConfig(
    filename="honeypot.log",
    filemode='a',
    format='%(asctime)s,%(msecs)03d %(levelname)s %(message)s',
    level=logging.WARNING
)

server = snap7.server.Server()

DB_BASE = 800
MK_BASE = 8400
PE_BASE = 4240
PA_BASE = 10560

DB_SIZE = 98
MK_SIZE = 64
PA_SIZE = 131

addresses = []
addresses.extend(range(DB_BASE, DB_BASE + DB_SIZE))
addresses.extend(range(MK_BASE, MK_BASE + MK_SIZE))
addresses.append(PE_BASE)
addresses.extend(range(PA_BASE, PA_BASE + PA_SIZE))

db_area = ctypes.create_string_buffer(12000)
mk_area = ctypes.create_string_buffer(256)
pe_area = ctypes.create_string_buffer(32)
pa_area = ctypes.create_string_buffer(256)

server.register_area(SrvArea.DB, 1, db_area)
server.register_area(SrvArea.MK, 1, mk_area)
server.register_area(SrvArea.PE, 1, pe_area)
server.register_area(SrvArea.PA, 1, pa_area)

synthesizer = load_synthesizer(filepath='category.pkl')

def get_offset_and_area(addr):
    if DB_BASE <= addr < DB_BASE + DB_SIZE:
        return (addr - DB_BASE) * 4, SrvArea.DB
    elif MK_BASE <= addr < MK_BASE + MK_SIZE:
        return addr - MK_BASE, SrvArea.MK
    elif addr == PE_BASE:
        return 0, SrvArea.PE
    elif PA_BASE <= addr < PA_BASE + PA_SIZE:
        return addr - PA_BASE, SrvArea.PA
    return None, None

def generate_synthetic_data(address_list):
    conditions = []
    for addr in address_list:
        conditions.append(
            Condition(
                num_rows=1,
                column_values={'address': addr}
            )
        )

    try:
        df = synthesizer.sample_from_conditions(
            conditions=conditions,
            max_tries_per_batch=200
        )
        
    except ValueError:
        logging.warning("Synthesizer failed, using zero fallback")
        df = pd.DataFrame({'address': address_list, 'data': 0})

    sampled = set(df['address'].tolist())

    missing = []
    for addr in address_list:
        if addr not in sampled:
            missing.append(addr)

    if missing:
        logging.warning(f"Zero fallback for {len(missing)} addresses: {missing}")
        fallback_df = pd.DataFrame({'address': missing, 'data': 0})
        df = pd.concat([df, fallback_df], ignore_index=True)

    df['offset'], df['area'] = zip(*df['address'].map(get_offset_and_area))

    return df

def write_to_memory(data_list):

    for d in data_list:
        area = d['area']
        offset = int(d['offset'])
        value = d['data']

        buffer = {SrvArea.DB: db_area,
                  SrvArea.MK: mk_area,
                  SrvArea.PE: pe_area,
                  SrvArea.PA: pa_area}[area]

        if area == SrvArea.DB:
            byte_data = struct.pack('>f', float(value))
            buffer[offset:offset + 4] = byte_data
        else:  
            byte_index = offset // 8
            bit_index = offset % 8
            current_byte = buffer[byte_index]
            if isinstance(current_byte, bytes):
                current_byte = current_byte[0]
            if int(value) % 2:
                current_byte |= (1 << bit_index)
            else:
                current_byte &= ~(1 << bit_index)
            buffer[byte_index] = current_byte

def get_matching_addresses(start, length):
    read_end = start + max(1, length)
    matches = []

    for addr in addresses:
        offset, area = get_offset_and_area(addr)
        if area is None:
            continue

        size = 4 if area == SrvArea.DB else 1

        if offset + size > start and offset < read_end:
            matches.append(addr)

    return matches

logging.warning("Generating initial random data")
synthetic_data = generate_synthetic_data(addresses)
write_to_memory(synthetic_data.to_dict('records'))
logging.warning("Initial data written. Starting server.")

server.start(1102)
EVC_DATA_READ = 0x00020000
EVC_DATA_WRITE = 0x00040000

try:
    while True:
        event = server.pick_event()
        if event:
            logging.warning(server.event_text(event))

            # READ
            if event.EvtCode == EVC_DATA_READ and event.EvtRetCode == 0:
                area = event.EvtParam1
                start = event.EvtParam2
                length = event.EvtParam3
                matching = get_matching_addresses(start, length)
                logging.warning(f"Matched addresses: {matching}")
                if matching:
                    new_data = generate_synthetic_data(matching)
                    write_to_memory(new_data.to_dict('records'))

            # WRITE
            elif event.EvtCode == EVC_DATA_WRITE and event.EvtRetCode == 0:
                area = event.EvtParam1
                start = event.EvtParam2
                length = event.EvtParam3
                buffer = {SrvArea.DB: db_area,
                          SrvArea.MK: mk_area,
                          SrvArea.PE: pe_area,
                          SrvArea.PA: pa_area}.get(area)
                if buffer:
                    data = buffer[start:start + length]
                    logging.warning(f"Data written: {list(data)}")

        time.sleep(0.01)

except KeyboardInterrupt:
    server.stop()
    server.destroy()
    logging.warning("Server stopped")
