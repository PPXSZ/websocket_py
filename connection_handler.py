# -*- coding: utf-8 -*-#

# -----------------------
# Name:         ConnectionHandler
# Description:  处理连接请求 接受数据
# Author:       mao
# Date:         2020/7/21
# -----------------------
from threading import Thread
import base64
import hashlib


class ConnectionHandler(Thread):
    def __init__(self, client, addr, on_data=None):
        super().__init__()
        self.client = client
        self.f = client.makefile(mode='rw')
        self.addr = addr
        self.on_data = on_data

    def run(self):
        # 获取stat line
        stat_line = self.f.readline()
        if not stat_line:
            return
        # 头部字段
        headers = {}

        line = self.f.readline()
        while line and ':' in line:
            header_key, header_val = line.split(':', 1)
            headers[header_key] = header_val.strip()
            line = self.f.readline()

        if 'Sec-WebSocket-Key' not in headers:
            # 不是websocket 直接关闭连接
            print('websocket error!')
            self.f.close()
            return

        key = self.generate_key(headers['Sec-WebSocket-Key'])

        res_headers = "HTTP/1.1 101 Switching Protocols\r\n" \
                      "Upgrade: websocket\r\n" \
                      "Connection: Upgrade\r\n" \
                      f"Sec-WebSocket-Accept: {key.decode('utf-8')}\r\n\r\n"

        # 发送响应
        self.f.write(res_headers)
        self.f.flush()

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
        payload_len = packet[1] & 0b1111111

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
        mask = packet[offset:offset + 4]
        data = packet[offset + 4:]

        # 使用掩码进行处理
        real_data = bytearray([v ^ mask[i % 4] for i, v in enumerate(data)])

        return str(real_data, encoding='utf-8')

    def handle(self):
        while True:
            packet = self.client.recv(1024)
            if not packet:
                continue
            # 获取实际的数据
            data = self.parse_data(packet)

            # 回调
            if not self.on_data:
                self.send_msg(data)

    def send_msg(self, msg):
        """
        发送 websocket 消息
        """
        import struct
        # ! 网络大端传输
        # B 无符号字符 1字节
        # H 无符号短整型 2字节
        # Q 无符号长长整形 8字节

        # 1         000     0001
        # 没有数据了 没有扩展  文本帧
        res = struct.pack('!B', 0b10000001)

        # 长度处理
        msg_len = len(msg)
        if msg_len < 126:
            # 放入真实的长度
            res += struct.pack('!B', msg_len)
        elif msg_len == 126:
            # 后面两个字节是长度
            res += struct.pack('!B', 126)
            res += struct.pack("!H", msg_len)
        elif msg_len == 127:
            # 后面8个字节才是
            res += struct.pack('!B', 126)
            res += struct.pack("!Q", msg_len)

        # 添加实际的数据
        res += struct.pack(f'!{msg_len}s', msg.encode('utf-8'))
        self.client.send(res)

    def generate_key(self, sec_key):
        """
        响应websocket请求的
        """
        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        return base64.b64encode(hashlib.sha1((sec_key + magic).encode('utf-8')).digest())
