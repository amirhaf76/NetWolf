import threading
import socket
import os
from concurrent.futures import ThreadPoolExecutor
from math import ceil

ENCODE_MODE = 'utf-8'
ERROR_ENCODING = 'backslashreplace'
ADDR_MESSAGE_LENGTH = 1
CMD_MESSAGE_LENGTH = 1
DATA_MESSAGE_LENGTH = 3
DATA_MESSAGE_ORDER = 'big'


# functions
def new_name_file(name: str, path: str):
    index = 0
    while name in os.listdir(path):
        index += 1
        if index == 1:
            dot = name.rfind('.', 0, len(name))
            if dot == -1:
                dot = len(name)
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


def get_ith_mb_from(path: str, name: str, number: int):
    file = open(path + os.sep + name, 'rb')

    file.seek((10 ** 6) * number, 0)
    temp = file.read(10 ** 6)
    file.close()
    # print(temp)
    return temp


def extract_address_port_format(raw_data: bytes):
    """

    :param raw_data: bytes of data which have certain format as ...|(ip, pn, ipp, ppn)|...
    :return: List of tuple which include 4 element. (ip, pn, ipp, ppn)
    """
    str_meg = raw_data.decode(ENCODE_MODE, ERROR_ENCODING)
    str_list = str_meg.split('|')
    res = []
    for t in str_list:
        temp_list = t.split(',')
        if len(temp_list) == 4:
            ipp = None
            ppn = None

            if not temp_list[2].strip(' \'') == 'None':
                ipp = temp_list[2].strip(' \'')
            if not temp_list[3].strip(' \'') == 'None':
                ppn = int(temp_list[3])

            temp_tuple = (temp_list[0].strip(' \''),
                          int(temp_list[1]),
                          ipp,
                          ppn)

            res.append(temp_tuple)
        else:
            print("not found")
    return res


def extract_source_and_destination(raw_data: bytearray):
    src_des = extract_address_port_format(raw_data)
    dict_src_dec = {'src': src_des[0],
                    'des': src_des[1]}
    return dict_src_dec


def extract_directory_message(dir_mes: bytes):
    """
    extract directory from directory message
    :param dir_mes: it's bytes that it needs to decode
    its format is " ... |ip, portNumber, ipProxy, proxy port number| ... "
    :return: dict
    """
    addr = extract_address_port_format(dir_mes)
    dir_list = []
    for ip, pn, ipp, ppn in addr:
        dir_list.append((ip, (pn, ipp, ppn)))

    return dict(dir_list)


def extract_message(skt: socket.socket):
    command_siz = int.from_bytes(skt.recv(CMD_MESSAGE_LENGTH), 'big', signed=False)
    addr_siz = int.from_bytes(skt.recv(ADDR_MESSAGE_LENGTH), 'big', signed=False)
    data_siz = int.from_bytes(skt.recv(DATA_MESSAGE_LENGTH), 'big', signed=False)

    command = skt.recv(command_siz).decode(ENCODE_MODE, ERROR_ENCODING)
    addr = None
    if not addr_siz == 0:
        addr = extract_source_and_destination(bytearray(skt.recv(addr_siz)))
    data = skt.recv(data_siz)

    return command, addr, bytearray(data)


def get_checking_number(meg: bytes):
    meg = meg.decode(ENCODE_MODE, ERROR_ENCODING)
    half = len(meg) // 2
    part1 = meg[:half]
    part2 = meg[half:]

    res = part1.__hash__() + part2.__hash__()

    return res


def is_there_file(path: str, name: str):
    return name in os.listdir(path)


def get_size_of_file(path: str, name: str):
    """
    get size of file in MB
    :param path: path of file
    :param name: name of file
    :return: if there is file, it will return size,
    if there isn't, it will return None
    """
    if is_there_file(path, name):

        file = open(path + os.sep + name, 'rb')
        size = ceil(file.seek(0, 2) / (10 ** 6))
        file.close()

        return size
    else:
        return None


def assemble_files(path: str, name: str, new_path: str, new_name: str):
    new_file = open(new_path + os.sep + new_name, 'wb')

    index = 0
    temp_list = []
    base_name = name

    while name in os.listdir(path):
        temp_list.append(name)

        temp_file = open(path + os.sep + name, 'rb')
        new_file.write(temp_file.read())
        temp_file.close()

        dot = name.rfind('.', 0, len(name))
        if dot == -1:
            dot = len(name)

        index += 1
        name = base_name[:dot] + f'({index})' + base_name[dot:]

    for n in temp_list:
        os.remove(path + os.sep + n)
    new_file.close()


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
        self.__is_end = False

    def run(self):
        self.__start_server()

    def stop(self):
        self.__is_end = True
        self.__tcp_socket.close()

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

        print('[TCP Server] Server has been started')
        print('[TCP Server] IP:{} port number:{} path:{}'.
              format(self.host_info[0], self.host_info[1], self.path))
        while not self.__is_end:
            try:
                temp_socket = self.__tcp_socket.accept()
                self.__pool.submit(self.__client_handler, temp_socket[0])
            except OSError:
                if self.__is_end:
                    print('[TCP Server] Server stop manually')
                else:
                    print(OSError)

    def __client_handler(self, skt: socket.socket):
        command, src_des, raw_data = extract_message(skt)

        if command == DownloadData.command:
            name = extract_download_data(raw_data)
            if is_there_file(self.path, name):
                self.__send(skt, name, src_des)
            else:
                self.__response_not_found(skt, name)
        skt.close()

    def __send(self, skt: socket.socket, name: str, src_des):

        size = get_size_of_file(self.path, name)
        for part in range(size):
            # use get_ith_mb_from function
            data_file = get_ith_mb_from(self.path, name, part)
            rsp_data = prepare_response_data(f'{name}_part_{size}', bytearray(data_file))
            rsp_mes = ResponseData(rsp_data, src_des[0], src_des[1])
            # skt.send

        # send final response
        rsp_done = prepare_response_data(f'done_{name}', bytearray(0))
        skt.send(ResponseData(rsp_done).get_data())

    def __response_not_found(self, skt: socket.socket, name):
        data_res = bytearray(f'not found {name}', self.__ENCODE_MODE, self.__ERROR_ENCODING)
        resp_nf = ResponseData(data_res).get_data()
        skt.send(resp_nf)


class UdpServer(Server):
    # 1 Mib
    __size_of_message = 1024 * 500
    __udp_socket = None

    def __init__(self, path: str, dir_l: list, addr=None, port=0):
        Server.__init__(self)
        self.path = path
        self.host_info = (addr, port)
        self.dir = dir_l
        self.__is_end = False

    def run(self):
        self.__start_server()

    def stop(self):
        self.__is_end = True
        self.__udp_socket.close()

    def __start_server(self):
        addr = self.host_info[0]
        port = self.host_info[1]
        if addr is None:
            addr = socket.gethostbyname(socket.gethostname())

        self.__udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__udp_socket.bind((addr, port))
        self.host_info = self.__udp_socket.getsockname()

        print('[UDP Server] Server has been started')
        print('[UDP Server] IP:{} port number:{} path:{}'.
              format(self.host_info[0], self.host_info[1], self.path))
        while not self.__is_end:
            try:
                command, rec_data, dest = extract_message(self.__udp_socket, getaddr=True)
                self.__client_handler(command, rec_data, dest)
            except OSError:
                if self.__is_end:
                    print('[UDP Server] Server stop manually')
                else:
                    print(OSError)

    def __client_handler(self, command: str, rec_data: bytes, dest: str):
        check_n, raw_data = extract_check_number(rec_data)
        if check_n == get_checking_number(rec_data):
            if command == DirectoryData.command:
                self.dir.append(extract_directory_message(raw_data))


class Message:
    command = '<command>'

    def __init__(self, message_data: bytearray, server_info: tuple = None, proxy_server_info: tuple = None):
        self.message_data = message_data
        self.server_info = server_info
        self.proxy_server_info = proxy_server_info

    def get_data(self):
        """
        pn port number
        ipp ip proxy
        ppn proxy port number
        addresses: ip, pn, ipp, ppn

        size of command - size of addresses - size of data -     command      -    addresses       -     data
             1B         -      1B           -      3B      - size of commandB - size of addressesB - size of dataB
        """
        temp = '{ip}, {pn}, {ipp}, {ppn}'.format(ip=self.server_info[0],
                                                 pn=self.server_info[1],
                                                 ipp=self.proxy_server_info[0],
                                                 ppn=self.proxy_server_info[1])
        command = bytearray(self.command, ENCODE_MODE, ERROR_ENCODING)
        servers_info = bytearray(temp, ENCODE_MODE, ERROR_ENCODING)

        # size of command - size of addresses 2Bytes
        packet = bytearray([len(command), len(servers_info)])

        # size of data 3Bytes
        packet += bytearray(int.to_bytes(len(self.message_data),
                                         DATA_MESSAGE_LENGTH,
                                         DATA_MESSAGE_ORDER))
        # command      -    addresses       -     data
        packet += command + servers_info + self.message_data
        return packet

    def __str__(self):
        temp = '{ip}, {pn}, {ipp}, {ppn}'.format(ip=self.server_info[0],
                                                 pn=self.server_info[1],
                                                 ipp=self.proxy_server_info[0],
                                                 ppn=self.proxy_server_info[1])
        command = bytearray(self.command, ENCODE_MODE, ERROR_ENCODING)
        servers_info = bytearray(temp, ENCODE_MODE, ERROR_ENCODING)
        return 'size:\n' \
               '      command: {sc}\n' \
               '    addresses: {sa}\n' \
               '         data: {sd}\n' \
               'info:\n' \
               '      command: {ic}\n' \
               '    addresses:\n' \
               '             destination: {ias}, \n' \
               '                   proxy: {iad}\n' \
               '         data: {id}'.format(sc=len(command),
                                            sa=len(servers_info),
                                            sd=len(self.message_data),
                                            ic=self.command,
                                            ias='{},{}'.format(self.server_info[0],
                                                               self.server_info[1]),
                                            iad='{},{}'.format(self.proxy_server_info[0],
                                                               self.proxy_server_info[1]),
                                            id=self.message_data)


class GetData(Message):

    def __init__(self, get_data: bytearray, server_info: tuple = None, proxy_server_info: tuple = None):
        Message.__init__(self, get_data, server_info, proxy_server_info)
        self.command = 'GET'


class DownloadData(Message):

    def __init__(self, dwn_data: bytearray, server_info: tuple = None, proxy_server_info: tuple = None):
        Message.__init__(self, dwn_data, server_info, proxy_server_info)
        self.command = 'DOWNLOAD'


class ResponseData(Message):

    def __init__(self, res_data: bytearray, server_info: tuple = None, proxy_server_info: tuple = None):
        Message.__init__(self, res_data, server_info, proxy_server_info)
        self.command = 'RSP'


class DirectoryData(Message):
    # todo complete directory data, it needs to define its format
    def __init__(self, dir_data: bytearray, server_info: tuple = None, proxy_server_info: tuple = None):
        Message.__init__(self, dir_data, server_info, proxy_server_info)
        self.command = 'DIR'


class File:
    def __init__(self, name, path):
        self.name = name
        self.path = path

    def save_data(self, data: bytearray):
        file = self.__open_file()

        file.write(data)

        file.close()

    def save_list_of_data(self, data_list: list):
        file = self.__open_file()

        for data in data_list:
            file.write(data)

        file.close()

    def __open_file(self):
        name = new_name_file(self.name, self.path)
        __f = open(self.path + '\\' + name, 'wb')
        return __f

    def __str__(self):
        pass  # todo complete str of class file


class Node:
    node_list = list()

    def __init__(self, name: str, ip: str, path: str):
        self.name = name
        self.ip = ip
        self.path = path

    def start_tcp_server(self):
        pass

    def start_udp_server(self):
        pass

    def __download_file(self, name: str):
        pass

    def __create_get_message(self):
        pass

    def __create_discovery_message(self):
        pass

    def __create_response_message(self):
        pass

    def __send_discover(self, discovery):
        pass

    def __update_list(self, node_list):
        pass

    def __serialize_data(self, s_date):
        pass

    def __deserialize_data(self, s_data):
        pass

    def __handle_response(self):
        pass

    def __save_file(self):
        pass

    def __chose_best(self):
        pass

    def __reassemble_file(self):
        pass


class NetWolf:
    """
    This is main class of NetWolf project
    date: 6/8/2020
    author: Amirhosein Amir Firouzkouhi ( 9528007)
    """

    def __init__(self):
        print('NetWolf 1398-1399')
        self.port = int(input('Please enter port number: '))
        self.dir = input('Please enter directory of list: ')

    def __start_user_command(self):
        pass

    def __str__(self):
        return "Net wolf < version 1>"


# end of classes

def prepare_directory_message(addr_dict: dict):
    """
    dict = { 'ip' : (portNum, 'ipProxy', proxyPortNumber) or
     'ip' : (portNum)}

    :param addr_dict:
    :return: str string format of directory message
    """
    res = []
    for key in addr_dict.keys():
        value = addr_dict[key]
        if len(value) == 3:
            temp = '{ip}, {portNum}, {ipp}, {ppn}'.format(ip=key,
                                                          portNum=value[0],
                                                          ipp=value[1],
                                                          ppn=value[2])
            res.append(temp)
        else:
            return 'error in prepare_directory_message'
    return '|'.join(res)


def prepare_response_data(rsp_txt: str, rsp_raw_data: bytearray):
    """

    :param rsp_txt: length of rsp_message must be less than 255
    :param rsp_raw_data:
    :return:
    """
    rsp_txt = bytearray(rsp_txt, ENCODE_MODE, ERROR_ENCODING)
    rsp_txt_size = len(rsp_txt)
    rsp_raw_data_size = len(rsp_raw_data)
    return bytearray([rsp_txt_size, rsp_raw_data_size]) + rsp_txt + rsp_raw_data


def send_message_to(mes: Message):
    skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if mes.proxy_server_info is None:
        skt.sendto(mes.get_data(), mes.server_info)
    else:
        skt.sendto(mes.get_data(), mes.proxy_server_info)


def send_message_to_get_file(name: str, server_info: tuple, proxy_server_info: tuple = None):
    mes = GetData(bytearray(name, ENCODE_MODE, ERROR_ENCODING),
                  server_info,
                  proxy_server_info)
    send_message_to(mes)


def send_directory_message_to(dir_dict: dict, server_info: tuple, proxy_server_info: tuple = None):
    mes = prepare_directory_message(dir_dict)
    mes_data = DirectoryData(bytearray(mes, ENCODE_MODE, ERROR_ENCODING),
                             server_info,
                             proxy_server_info)
    send_message_to(mes_data)


def send_response_message_to(rsp: bytearray, server_info: tuple, proxy_server_info: tuple = None):
    resp_data = ResponseData(rsp,
                             server_info,
                             proxy_server_info)
    send_message_to(resp_data)


def download_file_from(name: str, server_info: tuple, proxy_server_info: tuple = None):
    raw_data = bytearray([len(name)]) + bytearray(name, ENCODE_MODE, ERROR_ENCODING)
    download_mes = DownloadData(raw_data,
                                server_info,
                                proxy_server_info)
    send_message_to(download_mes)


def extract_download_data(raw_data: bytearray):
    name_siz = raw_data[0]
    name = raw_data[1:name_siz + 1].decode(ENCODE_MODE, ERROR_ENCODING)
    return name


def extract_response_data(raw_data: bytearray):
    rsp_txt_size = raw_data[0]
    # rsp_data_size = raw_data[1]
    rsp_txt = raw_data[2:rsp_txt_size + 1].decode(ENCODE_MODE, ERROR_ENCODING)
    rsp_data = raw_data[rsp_txt_size + 1:]
    return rsp_txt, rsp_data


def extract_check_number(data_str: bytes):
    """
    1B size of check number, read check number's bytes,
     rest of that is data
    :param data_str:
    :return:
    """
    chk_number_size = data_str[0]
    chk_n = int.from_bytes(data_str[1:chk_number_size + 1], 'big', signed=True)
    raw_data = data_str[chk_number_size:]

    return chk_n, raw_data
