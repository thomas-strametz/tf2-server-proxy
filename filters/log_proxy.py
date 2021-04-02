import socket
import threading
import re
from filters_loader import load_filters
from filters.exceptions import DoNotForwardException
from rcon_packet import parse_cmd, RconPacket, SERVERDATA_AUTH, SERVERDATA_EXECCOMMAND, perform_rcon_authentication, send_rcon_packet, recv_rcon_multi_res


def add_default_port(cmd):
    if len(cmd) == 2:
        cmd.extend([':', '27015'])
    return cmd


class LogProxy(threading.Thread):

    def __init__(self, cfg):
        threading.Thread.__init__(self)
        self.cfg = cfg
        self.log_filters = load_filters(cfg, 'log_filters')
        self.real_log_targets = []
        self.start()

    def filter_rcon_command(self, req) -> str:
        cmd = parse_cmd(req)
        if cmd[0] == 'logaddress_add':
            cmd = add_default_port(cmd)
            if len(cmd) == 4:
                log_target = f'{cmd[1]}:{cmd[3]}'
                for real_log_target in self.real_log_targets:
                    if real_log_target == log_target:
                        raise DoNotForwardException(f'logaddress_add:  {log_target} is already in the list')
                self.real_log_targets.append(f'{log_target}')
                raise DoNotForwardException(f'logaddress_add:  {log_target}')
            else:
                raise DoNotForwardException('Usage:  logaddress_add ip:port')
        elif cmd[0] == 'logaddress_list':
            if len(self.real_log_targets) == 0:
                raise DoNotForwardException('logaddress_list:  no addresses in the list')
            else:
                entries = '\n'.join(self.real_log_targets)
                raise DoNotForwardException(f'logaddress_list: {len(self.real_log_targets)} entries\n{entries}')
        elif cmd[0] == 'logaddress_del':
            cmd = add_default_port(cmd)
            if len(cmd) == 4:
                log_target = f'{cmd[1]}:{cmd[3]}'
                try:
                    self.real_log_targets.remove(log_target)
                    raise DoNotForwardException(f'logaddress_del:  {log_target}')
                except ValueError as e:
                    raise DoNotForwardException(f'logaddress_del:  address {log_target} not found in the list')
            else:
                raise DoNotForwardException(f'Usage:  logaddress_del ip:port')
        elif cmd[0] == 'logaddress_delall':
            self.real_log_targets.clear()
            raise DoNotForwardException(f'logaddress_delall:  all addresses cleared')
        return req

    def get_address(self):
        return self.cfg['listen_address'], int(self.cfg['log_proxy_port'])

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(self.get_address())

            while True:
                data, address = sock.recvfrom(4096)
                if data.startswith(b'\xff' * 4) and data.endswith(b'\n\x00'):
                    data = data[4:-2]
                    match = re.match(r'((?:S.*L|RL)\s[0-9]{2}/[0-9]{2}/[0-9]{4}\s-\s[0-9]{2}:[0-9]{2}:[0-9]{2}:\s)(.*)', data.decode('ascii'))
                    if match is not None:
                        new_log = match.group(2)
                        print(new_log)
                        for instance in self.log_filters:
                            new_log = instance.filter_log(new_log)
                        print(new_log)
                        # result = b'\xff' * 4 + match.group(1).encode('ascii') + new_log.encode('ascii') + b'\n\x00'
                        # print(result)
        except Exception as e:
            print(f'Log proxy disabled: {e}')
