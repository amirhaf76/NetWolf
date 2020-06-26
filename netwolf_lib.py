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

DES = 'DES'
SRC = 'SRC'

NOT_FOUND_RESPONSE_TEXT = '<NOT FOUND>'
FOUND_RESPONSE_TEXT = '<FOUND>'
SENDING_WAS_FINISHED = '<SWF>'

BRIDGE_SIZE_READ = 5
BRIDGE_CLOSE = '<BRIDGE_CLOSE>'
BRIDGE_MAKE = '<BRIDGE_MAKE'


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
            pass
            # Todo need exception
    return res


def extract_source_and_destination(raw_data: bytearray):
    if not len(raw_data) == 0:
        src_des = extract_address_port_format(raw_data)
        dict_src_dec = {SRC: src_des[0],
                        DES: src_des[1]}
        return dict_src_dec
    return {SRC: None, DES: None}


def extract_message(skt: socket.socket):
    command_siz = int.from_bytes(skt.recv(CMD_MESSAGE_LENGTH), 'big', signed=False)
    addr_siz = int.from_bytes(skt.recv(ADDR_MESSAGE_LENGTH), 'big', signed=False)
    data_siz = int.from_bytes(skt.recv(DATA_MESSAGE_LENGTH), 'big', signed=False)

    command = skt.recv(command_siz).decode(ENCODE_MODE, ERROR_ENCODING)

    addr = extract_source_and_destination(bytearray(skt.recv(addr_siz)))
    data = skt.recv(data_siz)

    return command, addr, bytearray(data)


def make_directory_dictionary(dir_dict: bytes):
    """
    extract directory from directory message
    :param dir_dict: it's bytes that it needs to decode
    its format is " ... |ip, portNumber, ipProxy, proxy port number| ... "
    :return: dict
    """
    addr = extract_address_port_format(dir_dict)
    dir_list = []
    for ip, pn, ipp, ppn in addr:
        dir_list.append((ip, (pn, ipp, ppn)))

    return dict(dir_list)


def filter_directory_dictionary(base_ip: str, src: tuple, dir_dict: dict):
    if dir_dict.__contains__(base_ip):
        dir_dict.pop(base_ip)
    ip, pn, ipp, ppn = src
    dir_dict.update({ip: (pn, ipp, ppn)})
    return dir_dict


def get_checking_number(meg: bytes):
    meg = meg.decode(ENCODE_MODE, ERROR_ENCODING)
    half = len(meg) // 2
    part1 = meg[:half]
    part2 = meg[half:]

    res = part1.__hash__() + part2.__hash__()

    return res


def is_there_file(path: str, name: str):
    return name in os.listdir(path)


def get_byte_size_of_file(path: str, name: str):
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
        self.host_info = (addr, port, None, None)
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
        ip, pn = self.__tcp_socket.getsockname()
        self.host_info = (ip, pn, None, None)
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

        # ip, pn, ipp, ppn = src_des[DES]

        if command == DownloadData.command:
            name = extract_download_data(raw_data)
            if is_there_file(self.path, name):
                self.__send(name, src_des[DES], src_des[SRC])
            else:
                self.__response_not_found(name)

        skt.close()

    def __handle_bridge(self, in_skt: socket.socket, command: str, src_des: dict, raw_data: bytearray):

        check_mes, next_des = is_there_next_des(self.host_info, src_des[DES])

        if check_mes:
            out_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            out_skt.connect(next_des)

            out_skt.send(reassemble_mes(command, src_des, raw_data).get_data())

            command, src_des, raw_data = extract_message(in_skt)
            out_skt.send(reassemble_mes(command, src_des, raw_data).get_data())

            bridge = BridgeConnection(in_skt, out_skt)
            bridge.start()
        else:
            command, src_des, raw_data = extract_message(in_skt)
            if command == DownloadData.command:
                name = extract_download_data(raw_data)
                if is_there_file(self.path, name):
                    self.__send(name, src_des[DES], src_des[SRC])
                else:
                    self.__response_not_found(name)

    def __send(self, name: str, src: tuple, des: tuple):

        size = get_byte_size_of_file(self.path, name)

        for part in range(size):
            # use get_ith_mb_from function
            data_file = get_ith_mb_from(self.path, name, part)

            rsp_data = prepare_response_data(f'{name}_part_{size}', bytearray(data_file))
            rsp_mes = ResponseData(rsp_data, src, des)

            self.__tcp_socket.send(rsp_mes.get_data())

        # send final response
        self.__response_done(name, src, des)

    def __response_not_found(self, name):
        pass

    def __response_done(self, name, src: tuple, des: tuple):
        rsp_done = prepare_response_data(f'done_{name}', bytearray(0))
        self.__tcp_socket.send(ResponseData(rsp_done, src, des).get_data())


class UdpServer(Server):
    # 1 Mib
    __size_of_message = 1024 * 500
    __udp_socket = None

    def __init__(self, path: str,
                 dir_dict: dict,
                 dir_lock: threading.Lock,
                 ip=None, port=0, tcp_server: TcpServer = None):

        Server.__init__(self)
        self.path = path
        self.dir_dict = dir_dict
        self.dir_lock = dir_lock
        self.host_info = (ip, port)
        self.__is_end = False

        self.__tcp_server = tcp_server

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
                command, src_des, rec_data = extract_message(self.__udp_socket)
                self.__client_handler(command, src_des, rec_data)
            except OSError:
                if self.__is_end:
                    print('[UDP Server] Server stop manually')
                else:
                    print(OSError)

    def __client_handler(self, command: str, src_des: dict, rec_data: bytes):

        # Todo self.host_info is not enough, it needs proxy address
        check_mes, next_des = is_there_next_des(self.host_info, src_des[DES])

        if check_mes:
            func = {DownloadData.command: DownloadData,
                    GetData.command: GetData,
                    ResponseData.command: ResponseData,
                    DirectoryData.command: DirectoryData}
            mes = func[command](rec_data, src_des[SRC], src_des[DES])

            send_message_to(mes, next_des)
            return

        # get command
        if command == GetData.command:
            self.__handle_get_message(src_des, rec_data)
        elif command == DirectoryData.command:
            self.__handle_directory_message(src_des, rec_data)
        elif command == ResponseData.command:
            pass

    def __handle_get_message(self, src_des: dict, rec_data: bytes):
        # decode name
        name = rec_data.decode(ENCODE_MODE, ERROR_ENCODING)

        # find next_destination for routing
        send, next_des = is_there_next_des(self.host_info, src_des[SRC])

        # is there file
        if is_there_file(self.path, name):

            # preparing get response
            if self.__tcp_server is None:
                get_rsp = prepare_get_response(name, ('None', 0, 'None', 'None'))
            else:
                get_rsp = prepare_get_response(name, self.__tcp_server.host_info)

            # preparing response for sending file
            rsp = prepare_response_data(FOUND_RESPONSE_TEXT, get_rsp)

            # send data as an ResponseData
            send_response_message_to(rsp, src_des[DES], src_des[SRC], next_des)
        else:
            # preparing response for sending file
            rsp = prepare_response_data(FOUND_RESPONSE_TEXT, bytearray(0))

            # send data as an ResponseData
            send_response_message_to(rsp, src_des[DES], src_des[SRC], next_des)

    def __handle_directory_message(self, src_des: dict, rec_data: bytes):
        new_dir_dict = make_directory_dictionary(rec_data)
        new_dir_dict = filter_directory_dictionary(self.host_info[0], src_des[SRC], new_dir_dict)

        self.dir_lock.acquire()
        self.dir_dict.update(new_dir_dict)

        self.dir_dict = update_proxy_of_server(self.dir_dict, self.host_info[0])
        self.dir_lock.release()


class Message:
    command = '<command>'

    def __init__(self, message_data: bytearray, src: tuple, des: tuple):
        self.message_data = message_data
        self.src_server_info = src
        self.des_server_info = des

    def get_data(self):
        """
        pn port number
        ipp ip proxy
        ppn proxy port number
        addresses: ip, pn, ipp, ppn

        size of command - size of addresses - size of data -     command      -    addresses       -     data
             1B         -      1B           -      3B      - size of commandB - size of addressesB - size of dataB
        """
        temp1 = '{ip}, {pn}, {ipp}, {ppn}'.format(ip=self.src_server_info[0],
                                                  pn=self.src_server_info[1],
                                                  ipp=self.src_server_info[2],
                                                  ppn=self.src_server_info[3])
        temp2 = '{ip}, {pn}, {ipp}, {ppn}'.format(ip=self.des_server_info[0],
                                                  pn=self.des_server_info[1],
                                                  ipp=self.des_server_info[2],
                                                  ppn=self.des_server_info[3])
        command = bytearray(self.command, ENCODE_MODE, ERROR_ENCODING)
        servers_info = bytearray('|'.join((temp1, temp2)), ENCODE_MODE, ERROR_ENCODING)

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
        temp1 = '{ip}, {pn}, {ipp}, {ppn}'.format(ip=self.src_server_info[0],
                                                  pn=self.src_server_info[1],
                                                  ipp=self.src_server_info[2],
                                                  ppn=self.src_server_info[3])
        temp2 = '{ip}, {pn}, {ipp}, {ppn}'.format(ip=self.des_server_info[0],
                                                  pn=self.des_server_info[1],
                                                  ipp=self.des_server_info[2],
                                                  ppn=self.des_server_info[3])
        command = bytearray(self.command, ENCODE_MODE, ERROR_ENCODING)
        servers_info = bytearray('|'.join((temp1, temp2)), ENCODE_MODE, ERROR_ENCODING)
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
                                            ias='{},{},{},{}'.format(self.src_server_info[0],
                                                                     self.src_server_info[1],
                                                                     self.src_server_info[2],
                                                                     self.src_server_info[3]),
                                            iad='{},{},{},{}'.format(self.des_server_info[0],
                                                                     self.des_server_info[1],
                                                                     self.des_server_info[2],
                                                                     self.des_server_info[3]),
                                            id=self.message_data)


class GetData(Message):

    def __init__(self, get_data: bytearray, src: tuple, des: tuple):
        Message.__init__(self, get_data, src, des)
        self.command = 'GET'


class DownloadData(Message):

    def __init__(self, dwn_data: bytearray, src: tuple, des: tuple):
        Message.__init__(self, dwn_data, src, des)
        self.command = 'DOWNLOAD'


class ResponseData(Message):

    def __init__(self, rsp_data: bytearray, src: tuple, des: tuple):
        Message.__init__(self, rsp_data, src, des)
        self.command = 'RSP'


class DirectoryData(Message):
    # todo complete directory data, it needs to define its format
    def __init__(self, dir_data: bytearray, src: tuple, des: tuple):
        Message.__init__(self, dir_data, src, des)
        self.command = 'DIR'


class BridgeData(Message):
    # todo complete directory data, it needs to define its format
    def __init__(self, brg_data: bytearray, src: tuple, des: tuple):
        Message.__init__(self, brg_data, src, des)
        self.command = 'BRG'


def reassemble_mes(command, src_des, raw_data):
    func = {DownloadData.command: DownloadData,
            GetData.command: GetData,
            ResponseData.command: ResponseData,
            DirectoryData.command: DirectoryData}
    mes = func[command](raw_data, src_des[SRC], src_des[DES])

    return mes


class BridgeConnection:

    def __init__(self, side1: socket.socket, side2: socket.socket):
        self.side1 = side1
        self.side2 = side2
        self.running = False

    def start(self):
        self.running = True

        while self.running:
            command, src_des, raw_data = extract_message(self.side2)

            if command == BridgeData.command:
                statue = raw_data.decode(ENCODE_MODE, ERROR_ENCODING)
                if statue == BRIDGE_CLOSE:
                    self.running = False

            mes = reassemble_mes(command, src_des, raw_data)
            self.side1.send(mes.get_data())


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
        # todo complete str of class file
        pass


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


class NotMatchFormat(Exception):

    def __str__(self):
        print('Format was not matched')


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


def prepare_get_response(name: str, tcp_server_addr: tuple):
    get_name = bytearray(name, ENCODE_MODE, ERROR_ENCODING)
    get_name_size = len(get_name)
    ip, pn, ipp, ppn = tcp_server_addr
    get_addr = f'{ip},{pn},{ipp},{ppn}'
    get_addr = bytearray(get_addr, ENCODE_MODE, ERROR_ENCODING)
    get_addr_size = len(get_addr)
    return bytearray([get_name_size, get_addr_size]) + get_name + get_addr


def send_message_to(mes: Message, next_des: tuple):
    skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    skt.sendto(mes.get_data(), next_des)


def send_message_to_get_file(name: str, src_server: tuple, des_server: tuple, next_des: tuple):
    mes = GetData(bytearray(name, ENCODE_MODE, ERROR_ENCODING), src_server, des_server)
    send_message_to(mes, next_des)


def send_directory_message_to(dir_dict: dict, src_server: tuple, des_server: tuple, next_des: tuple):
    mes = prepare_directory_message(dir_dict)
    mes_data = DirectoryData(bytearray(mes, ENCODE_MODE, ERROR_ENCODING), src_server, des_server)
    send_message_to(mes_data, next_des)


def send_response_message_to(rsp: bytearray, src_server: tuple, des_server: tuple, next_des: tuple):
    resp_data = ResponseData(rsp, src_server, des_server)
    send_message_to(resp_data, next_des)


def recv_data(skt: socket.socket, path, name):
    running = True
    file = File(name, path)
    while running:
        command, src_des, raw_data = extract_message(skt)
        if command == ResponseData.command:
            txt, file_data = extract_response_data(raw_data)
            if txt == SENDING_WAS_FINISHED:
                break

            file.save_data(file_data)


def download_file_from(name: str, src: tuple, des: tuple, save_in: str, save_as: str):

    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    raw_data = bytearray([len(name)]) + bytearray(name, ENCODE_MODE, ERROR_ENCODING)
    download_mes = DownloadData(raw_data, src, des)

    if does_need_a_bridge(src, des):
        raw_data = bytearray(BRIDGE_MAKE, ENCODE_MODE, ERROR_ENCODING)
        bridge_mes = BridgeData(raw_data, src, des)

        skt.send(bridge_mes.get_data())

    skt.send(download_mes.get_data())

    recv_data(skt, save_in, save_as)


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


def extract_get_response_data(raw_data: bytearray):
    rsp_name_size = raw_data[0]
    rsp_name = raw_data[2:rsp_name_size+1].decode(ENCODE_MODE, ERROR_ENCODING)
    rsp_addr = extract_address_port_format(raw_data[rsp_name_size+1:])
    return rsp_name, rsp_addr[0]


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


def is_there_next_des(base: tuple, des: tuple):
    base_ip, base_pn, base_ipp, base_ppn = base
    des_ip, des_pn, des_ipp, des_ppn = des

    if base_ip == des_ip:
        return False, (base_ip, base_pn)
    elif des_ipp is None:
        return True, (des_ip, des_pn)
    elif des_ipp == base_ipp:
        return True, (des_ip, des_pn)
    elif not des_ipp == base_ipp:
        return True, (des_ipp, des_ppn)


def update_proxy_of_server(dir_dict: dict, node_ip: str):
    host = socket.gethostbyname(socket.gethostname())
    if dir_dict.__contains__(host) and dir_dict.__contains__(node_ip):
        pn = dir_dict[node_ip][0]
        dir_dict.update([(node_ip, (pn, host[0], host[1]))])
    return dir_dict


def does_need_a_bridge(src: tuple, des: tuple):
    src_ip, src_pn, src_ipp, src_ppn = src
    des_ip, des_pn, des_ipp, des_ppn = des

    if src_ipp == des_ipp:
        return False
    else:
        return True
