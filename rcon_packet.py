import socket
import math
import re


SERVERDATA_AUTH = 3
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_RESPONSE_VALUE = 0

STATIC_PACKET_FIELDS_SIZE = 10  # = 4 (packet_id) + 4 (packet_type) + 1 (null_terminator) + 1 (packet_terminator) in bytes
MAX_PACKET_SIZE = 4096
MAX_BODY_SIZE = MAX_PACKET_SIZE - STATIC_PACKET_FIELDS_SIZE


def parse_cmd(req) -> [str]:
    return re.split(r'\s+', req)


def stringify_cmd(cmd) -> str:
    return ' '.join(cmd)


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


def send_rcon_packets(conn, rcon_packets):
    for rcon_packet in rcon_packets:
        send_rcon_packet(conn, rcon_packet)


def perform_rcon_authentication(conn, rcon_packet) -> [RconPacket]:
    send_rcon_packet(conn, rcon_packet)
    return [recv_rcon_packet(conn), recv_rcon_packet(conn)]


def get_multi_response_rcon_body(rcon_packets) -> str:
    return ''.join(map(lambda packet: packet.body, rcon_packets))


def generate_multi_response_rcon_packets(id, type, body) -> [RconPacket]:
    num_packets = math.ceil(len(body) / MAX_BODY_SIZE)
    rcon_packets = []

    for _ in range(num_packets - 1):
        rcon_packets.append(RconPacket(id, type, body[:MAX_PACKET_SIZE]))
        body = body[MAX_PACKET_SIZE:]
    rcon_packets.append(RconPacket(id, type, body))

    return rcon_packets


def recv_rcon_multi_res(conn):
    res_packets = recv_rcon_packets(conn)
    return res_packets[0].id, get_multi_response_rcon_body(res_packets)


def send_rcon_multi_res(conn, id, body) -> str:
    send_rcon_packets(conn, generate_multi_response_rcon_packets(id, SERVERDATA_RESPONSE_VALUE, body))
