#!/usr/bin/python3
import socket
from threading import Thread
import hashlib
import base64


class Handler(Thread):
    def __init__(self, client, addr):
        super().__init__()
        self.client = client
        self.addr = addr

    def run(self):
        data = self.client.recv(1024)
        data = data.decode('utf-8')
        headers = {}
        # 切分出 状态行 和 headers
        stat, header_lines = data.split('\r\n', 1)
        for line in header_lines.split('\r\n'):
            if not line:
                continue
            header_key, header_val = line.split(':', 1)
            headers[header_key] = header_val

        if 'Sec-WebSocket-Key' not in headers:
            # 不是websocket 直接关闭连接
            print('websocket error!')
            self.client.close()

        key = self.generate_key(headers["Sec-WebSocket-Key"])

        res_headers = "HTTP/1.1 101 Switching Protocols\r\n" \
                      "Upgrade: websocket\r\n" \
                      "Connection: Upgrade\r\n" \
                      f"Sec-WebSocket-Accept: {key}\r\n\r\n"

        # 发送响应
        self.client.send(res_headers.encode(encoding='utf-8'))
        print(headers)

        # 开始监听socket
        self.handle()

    def parse_data(self, packet):
        """
        解析websocket数据包
        1-4: FIN RSV1 RSV2 RSV3
        5-8: opcode:
                0x0: 文本
                0x1: 文本
                0x2: 二进制数据
                0x3-7, 0xB-F: 无定义
                0x8: 关闭连接
                0x9: PING
                0xA: PONG

        9: MASK 是否经过掩码处理
        10-16: Payload len 数据长度
               if in [0-125] => 真实长度
               if == 126 => 后面 16b 无符号整形是长度
               if == 127 => 后面 64b 无符号整形是长度

        紧跟着 4B : Masking-Key
        """
        # 暂时忽略第一个字节

        # 0x7f = 0b1111111
        # 获取到第二个字节的后 7bit 信息
        payload_len = ord(packet[1]) & 0b1111111

        # 数据掩码偏移
        offset = 2
        if payload_len == 126:
            # 额外2B是真实长度
            offset += 2
        elif payload_len == 127:
            # 额外8B为真实长度
            offset += 8

        # 掩码数据 & 数据
        # mask : 4B
        # data : 剩下的
        mask = packet[offset:offset+4]
        data = packet[offset+4:]

        # 对data进行掩码处理


    def handle(self):
        while True:
            packet = self.client.recv(1024)
            # 获取实际的数据
            data = self.parse_data(packet)
            if not data:
                continue
            print(data)

    def generate_key(self, sec_key):
        """
        响应websocket请求的
        """
        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        sec_key_with_magic = sec_key + magic
        sha1res = hashlib.sha1(sec_key_with_magic).digest()
        return base64.b64encode(sha1res)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 9876))
    s.listen(5)
    while True:
        c, addr = s.accept()
        Handler(c, addr).start()


if __name__ == "__main__":
    main()
