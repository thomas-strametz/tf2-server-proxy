#!/usr/bin/env python3
import json
import os
import threading
import uuid
from filters_loader import load_filters
from filters.exceptions import DoNotForwardException
from rcon_packet import *

LOG_COUNTER = 1

FILTER_CHAIN = []


def filter_rcon_command(req) -> str:
    for instance in FILTER_CHAIN:
        req = instance.filter_rcon_command(req)

    return req


def filter_rcon_command_response(req, res) -> str:
    for instance in FILTER_CHAIN:
        try:
            req = instance.filter_rcon_command_response(req, res)
        except AttributeError as e:
            pass

    return res


def log_rcon_command(addr, orig_req, req, orig_res, res):
    global LOG_COUNTER
    os.makedirs(cfg['log_dir'], exist_ok=True)
    with open(f'{cfg["log_dir"]}/log_{LOG_COUNTER}.json', 'w') as log_file:
        obj = {
            'host': f'{addr[0]}:{addr[1]}',
            'orig_req': orig_req,
            'req': req,
            'orig_res': orig_res,
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

                req.dump()

                if req.type == SERVERDATA_AUTH:
                    send_rcon_packets(self.conn, perform_rcon_authentication(forward_conn, req))
                else:
                    orig_req = req.body
                    try:
                        req.body = filter_rcon_command(orig_req)
                    except DoNotForwardException as e:
                        if e.drop:
                            continue
                        send_rcon_multi_res(self.conn, req.id, e.body)
                        continue
                    send_rcon_packet(forward_conn, req)

                    res_id, orig_res = recv_rcon_multi_res(forward_conn)
                    res_body = filter_rcon_command_response(req.body, orig_res)
                    send_rcon_multi_res(self.conn, res_id, res_body)

                    if cfg['log']:
                        log_rcon_command(self.addr, orig_req, req.body, orig_res, res_body)


def main():
    global FILTER_CHAIN
    FILTER_CHAIN = load_filters(cfg, 'rcon_filters')

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
    print(json.dumps(cfg, indent=4, sort_keys=True))

    main()
