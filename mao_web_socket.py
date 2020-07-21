# -*- coding: utf-8 -*-#

# -----------------------
# Name:         mao_web_socket
# Description:  
# Author:       mao
# Date:         2020/7/21
# -----------------------
import socket
from connection_handler import ConnectionHandler


class MaoWebSocket:
    """
    提供 websocket 服务
    """
    def __init__(self, host='0.0.0.0', port=9876):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port

    def start(self):
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((self.host, self.port))
        self.s.listen(5)

        while True:
            c, addr = self.s.accept()
            ConnectionHandler(c, addr).start()
