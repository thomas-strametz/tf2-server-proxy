
class DoNotForwardException(Exception):

    def __init__(self, body, drop=False):
        Exception.__init__(self, body)
        self.body = f'{body}\n'
        self.drop = drop
