import socket
import threading
import json

from filters.exceptions import DoNotForwardException
from rcon_packet import parse_cmd

MAX_MSG_SIZE = 4096


class GameProxyClient(threading.Thread):

    def __init__(self, proxy, real_server):
        threading.Thread.__init__(self)
        self.proxy = proxy
        self.real_server = real_server
        self.sock = None

    def forward_to_real_server(self, data):
        start_thread = False
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            start_thread = True

        self.sock.sendto(data, self.real_server)
        if start_thread:
            self.start()

    def run(self) -> None:
        with self.sock as sock:
            while True:
                data = sock.recv(MAX_MSG_SIZE)
                self.proxy.respond_to_client(self, data)


class GameProxy(threading.Thread):

    def __init__(self, cfg):
        threading.Thread.__init__(self)
        self.cfg = cfg
        self.client_address_mapping = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.start()

    def filter_rcon_command(self, req) -> str:
        cmd = parse_cmd(req)
        print(cmd)
        if cmd[0] == 'game_proxy':
            if cmd[1] == 'list_clients':
                lines = []
                for address, client in self.client_address_mapping.items():
                    if client.sock is not None:
                        lines.append(f'{address} <-> {client.sock.getsockname()}')

                clients = "\n".join(lines)
                raise DoNotForwardException(f'game_proxy: clients\n{clients}')
            else:
                raise DoNotForwardException(f'game_proxy: unknown subcommand "{cmd[1]}"')
        return req

    def respond_to_client(self, proxy_client, data):
        for address, client in self.client_address_mapping.items():
            if proxy_client == client:
                self.sock.sendto(data, address)

    def run(self):
        with self.sock as sock:
            proxy_server = (self.cfg['listen_address'], int(self.cfg['listen_port']))
            real_server = (self.cfg['forward_address'], int(self.cfg['forward_port']))
            sock.bind(proxy_server)

            while True:
                data, address = sock.recvfrom(MAX_MSG_SIZE)

                try:
                    proxy_client = self.client_address_mapping[address]
                except KeyError as e:
                    proxy_client = GameProxyClient(self, real_server)
                    self.client_address_mapping[address] = proxy_client

                proxy_client.forward_to_real_server(data)


def main():
    cfg = json.loads(''.join(open('../proxy-config.json', 'r').readlines()))
    print(json.dumps(cfg, indent=4, sort_keys=True))
    gp = GameProxy(cfg)


if __name__ == '__main__':
    main()
