import logging


class BotLogger(logging.Logger):
    def __init__(self, name: str, level: int) -> None:
        super().__init__(name, level)
        self._init_stream_handler()

    def _init_stream_handler(self):
        fmt = "[%(asctime)s] %(levelname)-6s %(filename)s+%(lineno)-4d %(name)s: [%(thread)d] %(message)s"
        formatter = logging.Formatter(fmt, datefmt="%H:%M:%S")
        handler = logging.StreamHandler()
        handler.setLevel(self.level)
        handler.setFormatter(formatter)
        self.addHandler(handler)

    def init_file_handler(self, filename):
        fmt = "[%(asctime)s] %(levelname)-6s %(filename)s+%(lineno)-4d %(name)s: [%(thread)d] %(message)s"
        formatter = logging.Formatter(fmt, datefmt="%H:%M:%S")
        handler = logging.FileHandler(filename, delay=False)
        handler.setLevel(self.level)
        handler.setFormatter(formatter)
        self.addHandler(handler)


def get_logger(name, level = logging.NOTSET) -> BotLogger:
    return BotLogger(name, level)
