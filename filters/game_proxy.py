import socket
import threading
import json

from filters.exceptions import DoNotForwardException
from rcon_packet import parse_cmd

MAX_MSG_SIZE = 4096
SOCKET_TIMEOUT = 10


class GameProxyClient(threading.Thread):

    def __init__(self, proxy, real_server, client_address):
        threading.Thread.__init__(self)
        self.proxy = proxy
        self.real_server = real_server
        self.client_address = client_address
        self.sock = None

    def forward_to_real_server(self, data):
        start_thread = False
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(SOCKET_TIMEOUT)
            start_thread = True

        self.sock.sendto(data, self.real_server)
        if start_thread:
            self.start()

    def run(self) -> None:
        with self.sock as sock:
            try:
                while True:
                    data = sock.recv(MAX_MSG_SIZE)
                    self.proxy.respond_to_client(data, self.client_address)
            except socket.timeout as e:
                pass
        self.proxy.throw_away_client(self)


class GameProxy(threading.Thread):

    def __init__(self, cfg):
        threading.Thread.__init__(self)
        self.cfg = cfg
        self.client_address_mapping_lock = threading.Lock()
        self.client_address_mapping = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.start()

    def filter_rcon_command(self, req) -> str:
        cmd = parse_cmd(req)
        if len(cmd) >= 1 and cmd[0] == 'game_proxy':
            if len(cmd) < 2:
                raise DoNotForwardException(f'game_proxy: provide a subcommand')
            elif cmd[1] == 'clients':
                if len(cmd) < 3:
                    raise DoNotForwardException(f'game_proxy clients: provide a subcommand')
                elif cmd[2] == 'list':
                    lines = []
                    for address, client in self.client_address_mapping.items():
                        if client.sock is not None:
                            lines.append(f'{address} <-> {client.sock.getsockname()}')

                    clients = "\n".join(lines)
                    raise DoNotForwardException(f'game_proxy: clients\n{clients}')
                elif cmd[2] == 'del':
                    try:
                        address = (cmd[3], int(cmd[5]))
                    except (KeyError, IndexError) as e:
                        raise DoNotForwardException(f'game_proxy clients del <ip:port>')

                    self.client_address_mapping_lock.acquire()
                    try:
                        del self.client_address_mapping[address]
                        self.client_address_mapping_lock.release()
                    except KeyError as e:
                        self.client_address_mapping_lock.release()
                        raise DoNotForwardException(f'game_proxy clients del: Unknown client {address}')
                    raise DoNotForwardException(f'game_proxy clients del {address}')
            else:
                raise DoNotForwardException(f'game_proxy: unknown subcommand "{cmd[1]}"')
        return req

    def respond_to_client(self, data, client_address):
        self.sock.sendto(data, client_address)

    def throw_away_client(self, proxy_client):
        del_address = None
        for address, client in self.client_address_mapping.items():
            if client == proxy_client:
                del_address = address
                break

        self.client_address_mapping_lock.acquire()
        if del_address is not None:
            del self.client_address_mapping[del_address]
        self.client_address_mapping_lock.release()

    def run(self):
        with self.sock as sock:
            proxy_server = (self.cfg['listen_address'], int(self.cfg['listen_port']))
            real_server = (self.cfg['forward_address'], int(self.cfg['forward_port']))
            sock.bind(proxy_server)

            while True:
                data, address = sock.recvfrom(MAX_MSG_SIZE)

                if data == b'\xff\xff\xff\xffTSource Engine Query\x00':
                    # Those queries are used to retrieve basic server information
                    # Valve sends way to many of them
                    continue

                try:
                    proxy_client = self.client_address_mapping[address]
                except KeyError as e:
                    proxy_client = GameProxyClient(self, real_server, address)
                    self.client_address_mapping_lock.acquire()
                    self.client_address_mapping[address] = proxy_client
                    self.client_address_mapping_lock.release()

                proxy_client.forward_to_real_server(data)


def main():
    cfg = json.loads(''.join(open('../proxy-config.json', 'r').readlines()))
    print(json.dumps(cfg, indent=4, sort_keys=True))
    gp = GameProxy(cfg)
    gp.filter_rcon_command('game_proxy clients del 129.0.0.1 : 1234')


if __name__ == '__main__':
    main()
