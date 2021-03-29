import json
import socket
import threading
import math
import uuid
import os


SERVERDATA_AUTH = 3
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_RESPONSE_VALUE = 0

STATIC_PACKET_FIELDS_SIZE = 10  # = 4 (packet_id) + 4 (packet_type) + 1 (null_terminator) + 1 (packet_terminator) in bytes
MAX_PACKET_SIZE = 4096
MAX_BODY_SIZE = MAX_PACKET_SIZE - STATIC_PACKET_FIELDS_SIZE

LOG_COUNTER = 1


class RconPacket:

    def __init__(self, id, type, body):
        self.id = id
        self.type = type
        self.body = body

    def get_packet_size(self) -> int:
        return STATIC_PACKET_FIELDS_SIZE + len(self.body)

    def dump(self):
        print(f'size = {self.get_packet_size()}, id = {self.id}, type = {self.type}, body = {self.body}')

    def to_bytes(self) -> bytes:
        packet_size = self.get_packet_size()
        data = bytearray()
        data.extend(int.to_bytes(packet_size, byteorder='little', length=4, signed=True))
        data.extend(int.to_bytes(self.id, byteorder='little', length=4, signed=True))
        data.extend(int.to_bytes(self.type, byteorder='little', length=4, signed=True))
        data.extend(bytes(self.body, 'ascii'))
        data.extend(b'\x00')
        data.extend(b'\x00')
        return bytes(data)


def recv_rcon_packet(conn) -> RconPacket:
    packet_size = int.from_bytes(conn.recv(4, socket.MSG_WAITALL), byteorder='little', signed=True)
    remaining_packet = conn.recv(packet_size, socket.MSG_WAITALL)

    packet_id = int.from_bytes(remaining_packet[0:4], byteorder='little', signed=True)
    packet_type = int.from_bytes(remaining_packet[4:8], byteorder='little', signed=True)

    packet_body_end = packet_size - 2
    if packet_body_end <= 8:
        packet_body = ''
    else:
        packet_body = str(remaining_packet[8:packet_body_end].split(b'\x00')[0], 'ascii')
    return RconPacket(packet_id, packet_type, packet_body)


def recv_rcon_packets(conn) -> [RconPacket]:
    rcon_packets = []

    trash_id = 999999
    send_rcon_packet(conn, RconPacket(trash_id, SERVERDATA_RESPONSE_VALUE, ''))  # send trash packet

    while True:
        rcon_packet = recv_rcon_packet(conn)
        if rcon_packet.id == trash_id:
            _ = recv_rcon_packet(conn)  # receive trash packet
            break
        rcon_packets.append(rcon_packet)

    return rcon_packets


def send_rcon_packet(conn, rcon_packet: RconPacket):
    return conn.sendall(rcon_packet.to_bytes())


def extract_body_of_rcon_packets(rcon_packets) -> str:
    return ''.join(map(lambda packet: packet.body, rcon_packets))


def generate_rcon_packets(id, type, body) -> [RconPacket]:
    num_packets = math.ceil(len(body) / MAX_BODY_SIZE)
    rcon_packets = []

    for _ in range(num_packets - 1):
        rcon_packets.append(RconPacket(id, type, body[:MAX_PACKET_SIZE]))
        body = body[MAX_PACKET_SIZE:]
    rcon_packets.append(RconPacket(id, type, body))

    return rcon_packets


def filter_input(req) -> str:
    return req


def filter_output(req, res) -> str:
    return res


def log_rcon_command(addr, req, res):
    global LOG_COUNTER
    os.makedirs(cfg['log_dir'], exist_ok=True)
    with open(f'{cfg["log_dir"]}/log_{LOG_COUNTER}.json', 'w') as log_file:
        obj = {
            'host': f'{addr[0]}:{addr[1]}',
            'req': req,
            'res': res
        }
        log_file.write(json.dumps(obj))
    LOG_COUNTER = LOG_COUNTER + 1


class RconClient(threading.Thread):

    def __init__(self, conn, addr):
        threading.Thread.__init__(self)
        self.conn = conn
        self.addr = addr

    def run(self) -> None:
        print(f'new rcon client {self.addr}')
        forward_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        forward_conn.connect((cfg['forward_address'], int(cfg['forward_port'])))

        with self.conn, forward_conn:
            while True:
                req = recv_rcon_packet(self.conn)

                if req.type == SERVERDATA_AUTH:
                    send_rcon_packet(forward_conn, req)
                    first_res = recv_rcon_packet(forward_conn)
                    send_rcon_packet(self.conn, first_res)
                    second_res = recv_rcon_packet(forward_conn)
                    send_rcon_packet(self.conn, second_res)
                else:
                    req.body = filter_input(req.body)
                    send_rcon_packet(forward_conn, req)
                    res_packets = recv_rcon_packets(forward_conn)

                    full_response = filter_output(req.body, extract_body_of_rcon_packets(res_packets))
                    for res_packet in generate_rcon_packets(res_packets[0].id, res_packets[0].type, full_response):
                        send_rcon_packet(self.conn, res_packet)

                    if cfg['log']:
                        log_rcon_command(self.addr, req.body, full_response)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((cfg['listen_address'], int(cfg['listen_port'])))
        s.listen()
        while True:
            conn, addr = s.accept()
            client = RconClient(conn, addr)
            client.start()


if __name__ == '__main__':
    cfg = json.loads(''.join(open('proxy-config.json', 'r').readlines()))
    cfg['log_dir'] = f'{cfg["log_dir"]}/{uuid.uuid4().__str__()}'
    print(cfg)

    main()
