class Filter:

    def __init__(self, cfg):
        self.cfg = cfg

    def filter_rcon_command(self, req) -> str:
        print('filter input')
        return req

    def filter_rcon_command_response(self, req, res) -> str:
        print('filter output')
        return res

    def filter_log(self, log) -> str:
        print('filter log')
        return log
