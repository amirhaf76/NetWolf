# class NetWolf:
#     """
#     This is main class of NetWolf project
#     date: 6/8/2020
#     author: Amirhosein Amir Firouzkouhi ( 9528007)
#     """
#
#     def start(self):
#         pass
#
#     def stop(self):
#         pass
#
#     def __start_user_command(self):
#         pass
#
#     def __str__(self):
#         return "Net wolf < version 1>"
#

# import socket
#
# from time import sleep
# def ser(port:int):
#     addr = socket.gethostbyname(socket.gethostname())
#     host_information = (addr, port)
#
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#
#     s.bind(host_information)
#
#     while True:
#         print('server is on')
#         data, ad = s.recvfrom(1024)
#         print('message{}'.format(data))
#         print('addr{}'.format(ad))
#         if data == 'exit':
#             break
#
#
#
# def server_tcp():
#     addr = socket.gethostbyname(socket.gethostname())
#
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.bind((addr, 2005))
#     host_info = (addr, s.getsockname()[1])
#     s.listen(5)
#     while True:
#         print('server is on')
#         c, ad = s.accept()
#         data = c.recv(1024)
#         meg = data.decode('utf-8', 'ignore')
#         print(meg[-4:])
#         print(str(meg[-4:]) == 'exit')
#         if str(meg[-4:]) == 'exit':
#             break
#     s.close()
#
# def cli_tcp(port, meg):
#     addr = socket.gethostbyname(socket.gethostname())
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     print(addr, port)
#     s.connect((addr, port))
#     l = bytearray(meg, 'utf-8', "ignore")
#
#     data = b'0'*(1024-len(l)) + l
#     s.send(data)
#     s.close()
#
#
# def cli():
#     addr = socket.gethostbyname(socket.gethostname())
#     port = 20005
#
#     host_information = (addr, port)
#     client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     meg = "hello server".encode()
#     print('send')
#     client.sendto(meg, host_information)
#
# def hello(a):
#     sleep(.5)
#     print(a[0])
#
# import threading
# from concurrent.futures import ThreadPoolExecutor
#
#
#
# t1 = threading.Thread(target=server_tcp)
#
# t2 = threading.Thread(target=cli_tcp, args=(2005, "hi"))
# t3 = threading.Thread(target=cli_tcp, args=(2005, "her"))
# t4 = threading.Thread(target=cli_tcp, args=(2005, "exit"))
# # t3 = ThreadPoolExecutor(max_workers=5)
#
#
# t1.start()
# sleep(2)
# t2.start()
# sleep(2)
# t3.start()
# sleep(2)
# t4.start()

import os


def new_name_file(name: str, path: str):
    index = 0
    while name in os.listdir(path):
        index += 1
        if index == 1:
            dot = name.rfind('.', 0, len(name))
            name = name[:dot] + f'({index})' + name[dot:]
        else:
            name = name.replace(f'({index - 1})', f'({index})')

    return name


def separate_to_mb(data: bytearray):
    mb = list()
    MB_SIZE = 1000000
    while True:
        if data.__len__() >= MB_SIZE:
            mb.append(data[0:MB_SIZE])
            data = data[MB_SIZE:]
        else:
            mb.append(data)
            break
    return mb


class File:

    def __init__(self, name: str, path: str):
        self.name = name
        self.path = path

    def save_data(self, data: bytearray):
        file = self._open_file(self.name, self.path)

        file.write(data)

        self._close_file(file)

    def save_list_of_data(self, data_list):
        file = self._open_file(self.name, self.path)

        for data in data_list:
            file.write(data)

        self._close_file(file)

    def _close_file(self, file):
        file.close()

    def _open_file(self, name: str, path):
        name = new_name_file(name, path)
        __f = open(path + '\\' + name, 'xb')

        return __f

    def __str__(self):
        pass

import threading

COMMAND_SIZE = 1

class Server(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def __start_server(self):
        raise NotImplementedError("Subclass must implement this abstract method")

import socket
import os
from concurrent.futures import ThreadPoolExecutor


class TcpServer(Server):
    __ENCODE_MODE = 'utf-8'
    __ERROR_ENCODING = 'backslashreplace'
    __pool = ThreadPoolExecutor(max_workers=5)
    __tcp_socket = None

    def __init__(self, path: str, addr=None, port=0):
        Server.__init__(self)
        self.path = path
        self.host_info = (addr, port)

    def run(self):
        self.__start_server()

    def __start_server(self):
        # get local address
        addr = self.host_info[0]
        port = self.host_info[1]
        if addr is None:
            addr = socket.gethostbyname(socket.gethostname())

        # create a socket
        self.__tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # bind a socket to the address and random port
        self.__tcp_socket.bind((addr, port))

        # save socket information
        self.host_info = self.__tcp_socket.getsockname()
        self.__tcp_socket.listen(2)

        while True:
            temp_socket = self.__tcp_socket.accept()
            self.__pool.submit(self.__client_handler, temp_socket[0])

    def __client_handler(self, socket_info: socket.socket):
        siz = int.from_bytes(socket_info.recv(1), 'big', signed=False)
        cmd_name = socket_info.recv(siz)
        cmd_name = cmd_name.decode(self.__ENCODE_MODE, self.__ERROR_ENCODING)

        # if cmd_name[:3] == 'GET':
        #     self.__send(cmd_name, cmd_name[3:])

    def __send(self, socket_info: socket.socket, name: str):
        """
        send file to client
        :param name: name of file
        :return: boolean
        """
        pass


class UdpServer(Server):

    def __init__(self, path: str, addr=None, port=0):
        Server.__init__(self)
        self.path = path
        self.host_info = (addr, port)

    def run(self):
        self.__start_server()

    def __start_server(self):
        addr = self.host_info[0]
        port = self.host_info[1]
        if addr is None:
            addr = socket.gethostbyname(socket.gethostname())

        self.__udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print(addr, port)
        self.__udp_socket.bind((addr, port))
        self.host_info = self.__udp_socket.getsockname()

        while True:
            data, dest = self.__udp_socket.recvfrom(1000)
            file = File('directory', self.path)
            print(bytearray(data))
            file.save_data(bytearray(data))



def cli():
    addr = socket.gethostbyname(socket.gethostname())
    port = 20005

    host_information = ('192.168.1.2', 13456)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    meg = "hello serverdsfsdf dsjfsdjfsdfsdfdsjfksdfjsdkff".encode()
    print('send')
    print(host_information)
    client.sendto(meg, host_information)

udp_s = UdpServer('F:\\', '192.168.1.6', 13456)
udp_s.start()
# print(udp_s.host_info)
cli()

