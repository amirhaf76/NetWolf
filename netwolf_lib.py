import threading
import socket
import os
from concurrent.futures import ThreadPoolExecutor
from math import ceil


# functions
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


def separate_to_mb(data_array: bytearray):
    mb = list()
    mb_size = 10 ** 6
    while True:
        if data_array.__len__() >= mb_size:
            mb.append(data_array[0:mb_size])
            data_array = data_array[mb_size:]
        else:
            mb.append(data_array)
            break
    return mb


def get_ith_mb_from(addr, number):
    file = open(addr, 'rb')

    file.seek((10 ** 6) * number, 0)
    temp = file.read(10 ** 6)
    file.close()
    # print(temp)
    return temp


# end of functions


# classes
class Server(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        self.__start_server()

    def __start_server(self):
        raise NotImplementedError("Subclass must implement this abstract method")


class TcpServer(Server):
    __ENCODE_MODE = 'utf-8'
    __ERROR_ENCODING = 'backslashreplace'
    __pool = ThreadPoolExecutor(max_workers=5)
    __tcp_socket = None

    # its better to give it address of localhost
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

        # start to listening
        self.__tcp_socket.listen(2)

        while True:
            temp_socket = self.__tcp_socket.accept()
            self.__pool.submit(self.__client_handler, temp_socket[0])

    def __client_handler(self, skt: socket.socket):
        siz = int.from_bytes(skt.recv(1), 'big', signed=False)
        cmd_name = skt.recv(siz)
        cmd_name = cmd_name.decode(self.__ENCODE_MODE, self.__ERROR_ENCODING)

        if cmd_name == 'GET':
            name = self.__find_file(skt)
            if not name is None:
                self.__send(skt, name)
            else:
                self.__response_not_found(skt, name)
        skt.close()

    def __send(self, skt: socket.socket, name: str):
        file = open(name, 'rb')
        number = ceil(file.seek(0, 2) / (10 ** 6))
        file.close()

        for part in range(number):
            # use get_ith_mb_from function
            data_file = get_ith_mb_from(name, number)

            resp = ResponseData(data_file)
            skt.send(resp.get_data())

        # send final response
        resp_done = bytearray(f'done {name}', self.__ENCODE_MODE, self.__ERROR_ENCODING)
        skt.send(ResponseData(resp_done).get_data())

    def __find_file(self, skt: socket.socket):
        siz = int.from_bytes(skt.recv(1), 'big', signed=False)
        name = skt.recv(siz).decode(self.__ENCODE_MODE, self.__ERROR_ENCODING)

        if name in os.listdir(self.path):
            return self.path + '\\' + name
        else:
            return None

    def __response_not_found(self, skt: socket.socket, name):
        data_res = bytearray(f'not found {name}', self.__ENCODE_MODE, self.__ERROR_ENCODING)
        resp_nf = ResponseData(data_res).get_data()
        skt.send(resp_nf)


class Message:
    command = '<command>'

    def __init__(self, message_data: bytearray):
        self.message_data = message_data

    def get_data(self):
        raise NotImplementedError("Subclass must implement this abstract method")

    def __str__(self):
        temp = bytearray(self.command, 'utf-8', 'backslashreplace')
        return 'size: {sc}\n' \
               'command: {c}\n' \
               'size of data: {sd}\n' \
               'data: {d}'.format(sc=len(temp), c=self.command, sd=len(self.message_data), d=self.message_data)


class GetData(Message):

    def __init__(self, get_data: bytearray):
        Message.__init__(self, get_data)
        self.command = 'GET'

    def get_data(self):
        """
        size - command - size of data - data
        1B   -   sizeB -      2B      - size of data B
        """
        temp = bytearray(self.command, 'utf-8', 'backslashreplace')
        packet = bytearray([len(temp)]) + temp
        packet += len(self.message_data)
        packet += self.message_data

        return packet


class ResponseData(Message):

    def __init__(self, res_data):
        Message.__init__(self, res_data)
        self.command = 'RSP'

    def get_data(self):
        """
        size - command - size of data - data
        1B   -   sizeB -      2B      - size of data B
        """
        temp = bytearray(self.command, 'utf-8', 'backslashreplace')
        packet = bytearray([len(temp)]) + temp
        packet += len(self.message_data)
        packet += self.message_data

        return packet


class DirectoryData(Message):
    # todo complete directory data, it needs to define its format
    def __init__(self, dir_data):
        Message.__init__(self, dir_data)
        self.command = 'DIR'

    def get_data(self):
        """
        size - command - size of data - data
        1B   -   sizeB -      2B      - size of data B
        """
        temp = bytearray(self.command, 'utf-8', 'backslashreplace')
        packet = bytearray([len(temp)]) + temp
        packet += len(self.message_data)
        packet += self.message_data

        return packet


class File:
    def __init__(self, name=None, path=None):
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

    def _open_file(self, name: str, path: str):
        name = new_name_file(name, path)
        __f = open(path + '\\' + name, 'wb')
        return __f

    def __str__(self):
        pass  # todo complete str of class file

# end of classes
