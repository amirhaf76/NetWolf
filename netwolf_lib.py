import threading
import socket
import os
from concurrent.futures import ThreadPoolExecutor
from math import ceil
from time import sleep
from IPython.display import clear_output
import shutil

ENCODE_MODE = 'utf-8'
ERROR_ENCODING = 'backslashreplace'

ADDR_MESSAGE_LENGTH = 1
CMD_MESSAGE_LENGTH = 1
DATA_MESSAGE_LENGTH = 3
DATA_MESSAGE_ORDER = 'big'

SHOW_STATE_BY_PRINTING_DIRECTLY = True

DES = 'DES'
SRC = 'SRC'

NOT_FOUND_RESPONSE_TEXT = '<NOT FOUND>'
FOUND_RESPONSE_TEXT = '<FOUND>'
SENDING_WAS_FINISHED = '<SWF>'

UDP_TIMER = 0.006
UDP_MESSAGE_SIZ = 500 * 100
UDP_PORT_NUMBER = 45500


class AddressIp:
    index = 0

    def __init__(self, ip: str, pn: int, proxy_ip: str = None, proxy_pn: int = None, name: str = None):
        self.ip = ip
        self.pn = pn
        self.proxy_ip = proxy_ip
        self.proxy_pn = proxy_pn

        if name is None:
            self.name = f'node{self.index}'
            AddressIp.index += 1
        else:
            self.name = name

    def __str__(self):
        return (f'ip: {self.ip}, ' +
                f'pn: {self.pn}, ' +
                f'proxy_ip: {self.proxy_ip}, ' +
                f'proxy_pn: {self.proxy_pn}, ' +
                f'name: {self.name}')

    def get_format(self):
        return (f'{self.ip}, ' +
                f'{self.pn}, ' +
                f'{self.proxy_ip}, ' +
                f'{self.proxy_pn}, ' +
                f'{self.name}')

    def get_file_format(self):

        if self.proxy_ip is not None:
            return (f'{self.name}' +
                    f' {self.ip}' +
                    f' {self.pn}' +
                    f' {self.proxy_ip}' +
                    f' {self.proxy_pn}')

        return (f'{self.name}' +
                f' {self.ip}' +
                f' {self.pn}')

    def __eq__(self, o) -> bool:
        if o is self:
            return True
        if not isinstance(o, AddressIp):
            return False
        res = o.ip == self.ip
        res = res and o.pn == self.pn
        res = res and o.proxy_ip == self.proxy_ip
        res = res and o.proxy_pn == self.proxy_pn
        return res


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

    return temp


def extract_address_ip_format(raw_data: bytes):
    """
    getting list of addresses in AddressIp
    :param raw_data: bytes of data which have certain format as ...|(ip, pn, ipp, ppn)|...
    :return: List of tuple which include 4 element. (ip, pn, ipp, ppn)
    """
    str_meg = raw_data.decode(ENCODE_MODE, ERROR_ENCODING)
    str_list = str_meg.split('|')
    res = []
    for t in str_list:
        temp_list = t.split(',')
        if len(temp_list) == 4 or len(temp_list) == 5:
            ipp = None
            ppn = None

            if not temp_list[2].strip(' \'') == 'None':
                ipp = temp_list[2].strip(' \'')
            if not temp_list[3].strip(' \'') == 'None':
                ppn = int(temp_list[3])

            if len(temp_list) == 5:
                temp_address_ip = AddressIp(temp_list[0].strip(' \''),
                                            int(temp_list[1]),
                                            ipp,
                                            ppn,
                                            temp_list[4].strip(' \''))
            else:
                temp_address_ip = AddressIp(temp_list[0].strip(' \''),
                                            int(temp_list[1]),
                                            ipp,
                                            ppn)

            res.append(temp_address_ip)
        else:
            print(f'[Error] extract_address_ip_format: {temp_list}')
    return res


def extract_source_and_destination(raw_data: bytearray):
    if not len(raw_data) == 0:
        src_des = extract_address_ip_format(raw_data)
        try:
            dict_src_dec = {SRC: src_des[0],
                            DES: src_des[1]}
            return dict_src_dec
        except IndexError as err:
            print(err)
    return {SRC: None, DES: None}


def extract_tcp_message(skt: socket.socket):
    command_siz = int.from_bytes(skt.recv(CMD_MESSAGE_LENGTH), 'big', signed=False)
    addr_siz = int.from_bytes(skt.recv(ADDR_MESSAGE_LENGTH), 'big', signed=False)
    data_siz = int.from_bytes(skt.recv(DATA_MESSAGE_LENGTH), 'big', signed=False)
    command = skt.recv(command_siz).decode(ENCODE_MODE, ERROR_ENCODING)

    addr = extract_source_and_destination(bytearray(skt.recv(addr_siz)))
    data = skt.recv(data_siz)

    return command, addr, bytearray(data)


def extract_udp_message(skt: socket.socket):
    buff = bytearray(skt.recv(500 * 100))

    start = 0
    end = CMD_MESSAGE_LENGTH
    command_siz = int.from_bytes(buff[start:end], 'big', signed=False)
    start = end
    end += ADDR_MESSAGE_LENGTH
    addr_siz = int.from_bytes(buff[start:end], 'big', signed=False)
    start = end
    end += DATA_MESSAGE_LENGTH
    data_siz = int.from_bytes(buff[start:end], 'big', signed=False)

    start = end
    end += command_siz
    command = buff[start:end].decode(ENCODE_MODE, ERROR_ENCODING)
    start = end
    end += addr_siz
    addr = extract_source_and_destination(bytearray(buff[start:end]))
    start = end
    end += data_siz
    data = buff[start:end]
    # print(command)
    # print(addr)
    # print(data)
    return command, addr, bytearray(data)


def make_directory_dictionary(dir_dict: bytes):
    """
    extract directory from directory message
    :param dir_dict: it's bytes that it needs to decode
    its format is " ... |ip, portNumber, ipProxy, proxy port number| ... "
    :return: dict
    """
    addr = extract_address_ip_format(dir_dict)
    dir_list = []
    for addr_ip in addr:
        dir_list.append((addr_ip.ip, addr_ip))

    return dict(dir_list)


def filter_directory_dictionary(base_address_ip: AddressIp, sender: AddressIp, dir_dict: dict):
    if dir_dict.__contains__(base_address_ip.ip):
        # print(dir_dict.__contains__(base_address_ip.ip))
        # print(base_address_ip.ip)
        # print(len(dir_dict))
        dir_dict.pop(base_address_ip.ip)
        # print(len(dir_dict))

    dir_dict.update({sender.ip: sender})

    return dir_dict


def get_checking_number(meg: bytes):
    """
    !!!!!!!!!!!!! not
    :param meg:
    :return:
    """
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
        return -1


def assemble_files(path: str, name: str, new_path: str, new_name: str, start_zero=False):
    # Todo maybe it go wrong because of running new_name file before
    new_file = open(new_path + os.sep + new_name, 'wb')

    index = 0
    temp_list = []
    base_name = name

    while name in os.listdir(path):
        temp_list.append(name)

        temp_file = open(path + os.sep + name, 'rb')
        new_file.write(temp_file.read())
        temp_file.close()

        if not start_zero:
            dot = name.rfind('.', 0, len(name))
            if dot == -1:
                dot = len(name)

            index += 1
            name = base_name[:dot] + f'({index})' + base_name[dot:]
        else:
            index += 1
            name = name[:len(name) - 1] + f'{index}'

    for n in temp_list:
        os.remove(path + os.sep + n)
    new_file.close()


# end of functions
def response_not_found(skt: socket.socket, name: str, src: AddressIp, des: AddressIp):
    name = name.encode(ENCODE_MODE, ERROR_ENCODING)
    rsp_done = prepare_response_data(NOT_FOUND_RESPONSE_TEXT, bytearray(name))
    skt.send(ResponseData(rsp_done, src, des).get_data())


def response_found(skt: socket.socket, name: str, src: AddressIp, des: AddressIp):
    rsp_done = prepare_response_data(FOUND_RESPONSE_TEXT, bytearray(name, ENCODE_MODE, ERROR_ENCODING))
    skt.send(ResponseData(rsp_done, src, des).get_data())


def response_done(skt: socket.socket, name: str, src: AddressIp, des: AddressIp):
    rsp_done = prepare_response_data(f'{SENDING_WAS_FINISHED}', bytearray(name, ENCODE_MODE, ERROR_ENCODING))
    skt.send(ResponseData(rsp_done, src, des).get_data())


# classes
class Server(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        self.__start_server()

    def __start_server(self):
        raise NotImplementedError("Subclass must implement this abstract method")


class TcpServer(Server):

    # its better to give it address of localhost
    def __init__(self, path: str, addr, port=0, name: str = None):
        Server.__init__(self)

        self.__pool = ThreadPoolExecutor(max_workers=5)
        self.__tcp_socket = None

        self.path = path
        self.host_info = AddressIp(addr, port, None, None, name)
        self.__is_end = False

        self.log = File(f'log_tcp_{addr}.txt', path)

    def run(self):
        try:
            self.__start_server()
        except socket.error as err:
            print(err)

    def stop(self):
        self.__is_end = True
        self.__pool.shutdown()
        self.__tcp_socket.close()

    def __start_server(self):
        # get local address
        addr = self.host_info.ip
        port = self.host_info.pn
        name = self.host_info.name
        if addr is None:
            addr = socket.gethostbyname(socket.gethostname())

        # create a socket
        self.__tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # bind a socket to the address and random port
        self.__tcp_socket.bind((addr, port))

        # save socket information
        ip, pn = self.__tcp_socket.getsockname()
        self.host_info = AddressIp(ip, pn, None, None, name)

        # start to listening
        self.__tcp_socket.listen(2)

        self.log.append_to_txt('[TCP Server] Server has been started\n')
        self.log.append_to_txt('[TCP Server] IP:{} port number:{} path:{}\n'.
                               format(self.host_info.ip, self.host_info.pn, self.path))

        if SHOW_STATE_BY_PRINTING_DIRECTLY:
            print('[TCP Server] Server has been started')
            print('[TCP Server] IP:{} port number:{} path:{}'.
                  format(self.host_info.ip, self.host_info.pn, self.path))

        while not self.__is_end:
            try:
                temp_socket = self.__tcp_socket.accept()
                self.__pool.submit(self.__client_handler, temp_socket[0])
            except OSError as err:
                if self.__is_end:
                    print('[TCP Server] Server stop manually\n')
                    self.log.append_to_txt('[TCP Server] Server stop manually\n')
                else:
                    print(err)
                    self.log.append_to_txt(err.strerror + '\n')

    def __client_handler(self, skt: socket.socket):
        command, src_des, raw_data = extract_tcp_message(skt)
        # print(command)
        # print(src_des[SRC], src_des[DES])
        # print(raw_data)
        if command == DownloadData.command:
            name = extract_download_data(raw_data)

            if is_there_file(self.path, name):
                # siz = get_byte_size_of_file(self.path, name)
                response_found(skt, name, src_des[DES], src_des[SRC])
                self.__send(skt, name, src_des[DES], src_des[SRC])
            else:
                response_not_found(skt, name, src_des[DES], src_des[SRC])
        skt.close()

    def __send(self, skt: socket.socket, name: str, src: AddressIp, des: AddressIp):

        size = get_byte_size_of_file(self.path, name)

        for part in range(size):
            # use get_ith_mb_from function
            data_file = get_ith_mb_from(self.path, name, part)

            rsp_data = prepare_response_data(f'{name}_part{part}', bytearray(data_file))
            rsp_mes = ResponseData(rsp_data, src, des)

            skt.send(rsp_mes.get_data())

        # send final response
        response_done(skt, name, src, des)


class UdpServer(Server):
    # 1 Mib
    __size_of_message = 500 * 100

    def __init__(self, path: str,
                 dir_dict: dict,
                 dir_lock: threading.Lock,
                 ip, port, tcp_server: TcpServer = None, name: str = None):

        Server.__init__(self)

        self.__udp_socket = None
        self.path = path
        self.dis_dict = dir_dict
        self.dir_lock = dir_lock
        self.host_info = AddressIp(ip, port, None, None, name)
        self.__is_end = False

        self.available_file_in_net = {}

        self.__tcp_server = tcp_server

    def run(self):
        try:
            self.__start_server()
        except socket.error as err:
            print(err)

    def stop(self):
        self.__is_end = True
        self.__udp_socket.close()

    def find_file(self, name):
        if self.isAlive():
            self.dir_lock.acquire()
            node_list = self.dis_dict.copy()
            self.dir_lock.release()

            for i in node_list.values():
                des_node: AddressIp = i

                send, hub = is_there_next_des(self.host_info,
                                              des_node)

                send_message_to_get_file(name, self.host_info,
                                         des_node, hub)

            sleep(1)

            if self.available_file_in_net.__contains__(name):
                # todo need to reload it
                return self.available_file_in_net[name]
            else:
                return None

    def __start_server(self):
        addr = self.host_info.ip
        port = self.host_info.pn
        name = self.host_info.name
        if addr is None:
            addr = socket.gethostbyname(socket.gethostname())

        self.__udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__udp_socket.bind((addr, port))
        temp_tuple = self.__udp_socket.getsockname()
        self.host_info = AddressIp(temp_tuple[0],
                                   temp_tuple[1],
                                   self.host_info.proxy_ip,
                                   self.host_info.proxy_pn,
                                   name)

        if SHOW_STATE_BY_PRINTING_DIRECTLY:
            print('[UDP Server] Server has been started')
            print('[UDP Server] IP:{} port number:{} path:{}'.
                  format(self.host_info.ip, self.host_info.pn, self.path))

        while not self.__is_end:
            try:
                command, src_des, rec_data = extract_udp_message(self.__udp_socket)
                self.__client_handler(command, src_des, rec_data)
            except OSError as err:
                if self.__is_end:
                    print('[UDP Server] Server stop manually')
                else:
                    print(err)
                    # self.log.append(err)

    def __client_handler(self, command: str, src_des: dict, rec_data: bytes):

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
            self.__handle_response_data(bytearray(rec_data))

    def __handle_get_message(self, src_des: dict, rec_data: bytes):
        # decode name
        name = rec_data.decode(ENCODE_MODE, ERROR_ENCODING)

        # is there file
        if is_there_file(self.path, name) and self.__tcp_server is not None:

            # find next_destination for routing
            send, next_des = is_there_next_des(self.host_info, src_des[SRC])

            # preparing get response
            get_rsp = prepare_get_response(name, self.__tcp_server.host_info)

            # preparing response for sending file
            rsp = prepare_response_data(FOUND_RESPONSE_TEXT, get_rsp)

            # send data as an ResponseData
            send_response_message_to(rsp, self.host_info, src_des[SRC], next_des)

    def __handle_directory_message(self, src_des: dict, rec_data: bytes):

        # extract addresses and make them dictionary
        new_dir_dict = make_directory_dictionary(rec_data)

        # adding sender and omit itself
        new_dir_dict = filter_directory_dictionary(self.host_info, src_des[SRC], new_dir_dict)

        self.dir_lock.acquire()

        # update addresses
        self.dis_dict.update(new_dir_dict)

        # update proxy
        update_proxy_of_server(self.dis_dict, self.host_info)

        self.dir_lock.release()

    def __handle_response_data(self, rec_data: bytearray):
        txt, temp_data = extract_response_data(rec_data)

        if txt == FOUND_RESPONSE_TEXT:
            name, addr = extract_get_response_data(temp_data)
            # todo update completley
            self.available_file_in_net.update({name: addr})


class Message:
    command = '<command>'

    def __init__(self, message_data: bytearray, src: AddressIp, des: AddressIp):
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
        temp1 = self.src_server_info.get_format()
        temp2 = self.des_server_info.get_format()
        command = bytearray(self.command, ENCODE_MODE, ERROR_ENCODING)
        servers_info = bytearray('|'.join((temp1, temp2)), ENCODE_MODE, ERROR_ENCODING)

        # size of command - size of addresses 1Bytes
        packet = bytearray(int.to_bytes(len(command),
                                        CMD_MESSAGE_LENGTH,
                                        DATA_MESSAGE_ORDER))

        packet += bytearray(int.to_bytes(len(servers_info),
                                         ADDR_MESSAGE_LENGTH,
                                         DATA_MESSAGE_ORDER))
        # size of data 3Bytes
        packet += bytearray(int.to_bytes(len(self.message_data),
                                         DATA_MESSAGE_LENGTH,
                                         DATA_MESSAGE_ORDER))
        # command      -    addresses       -     data
        packet += command + servers_info + self.message_data

        return packet

    def __str__(self):
        temp1 = self.src_server_info.get_format()
        temp2 = self.des_server_info.get_format()
        command = bytearray(self.command, ENCODE_MODE, ERROR_ENCODING)
        servers_info = bytearray('|'.join((temp1, temp2)), ENCODE_MODE, ERROR_ENCODING)
        return 'size:\n' \
               '      command: {sc}\n' \
               '    addresses: {sa}\n' \
               '         data: {sd}\n' \
               'info:\n' \
               '      command: {ic}\n' \
               '    addresses:\n' \
               '             src: {ias}, \n' \
               '             des: {iad}\n' \
               '         data: {id}'.format(sc=len(command),
                                            sa=len(servers_info),
                                            sd=len(self.message_data),
                                            ic=self.command,
                                            ias=self.src_server_info.get_format(),
                                            iad=self.des_server_info.get_format(),
                                            id=self.message_data)


class GetData(Message):

    command = 'GET'

    def __init__(self, get_data: bytearray, src: AddressIp, des: AddressIp):
        """
        get_data is byte array of file's name
        :param get_data:
        :param src:
        :param des:
        """
        Message.__init__(self, get_data, src, des)


class DownloadData(Message):
    command = 'DOWNLOAD'

    def __init__(self, dwn_data: bytearray, src: AddressIp, des: AddressIp):
        Message.__init__(self, dwn_data, src, des)


class ResponseData(Message):
    command = 'RSP'

    def __init__(self, rsp_data: bytearray, src: AddressIp, des: AddressIp):
        """
        response is always text + some data in byte array
        :param rsp_data:
        :param src:
        :param des:
        """
        Message.__init__(self, rsp_data, src, des)


class ListOfFileData(Message):
    command = 'LFD'

    def __init__(self, lfd_data: bytearray, src: AddressIp, des: AddressIp):
        Message.__init__(self, lfd_data, src, des)


class DirectoryData(Message):
    # todo complete directory data, it needs to define its format
    command = 'DIR'

    def __init__(self, dir_data: bytearray, src: AddressIp, des: AddressIp):
        Message.__init__(self, dir_data, src, des)


class File:
    def __init__(self, name, path):
        self.name = name
        self.path = path

    def append_to_binary(self, info: bytes):
        file = self.__open_file_for_appending(True)

        file.write(info)

        temp = file.name

        file.close()

        return temp

    def append_to_txt(self, txt: str):
        file = self.__open_file_for_appending(False)

        file.write(txt)

        temp = file.name

        file.close()

        return temp

    def save_data(self, data: bytearray):
        file = self.__open_new_file()

        file.write(data)

        temp = file.name

        file.close()

        return temp

    def save_list_of_data(self, data_list: list):
        file = self.__open_new_file()

        for data in data_list:
            file.write(data)

        temp = file.name

        file.close()

        return temp

    def __open_new_file(self):
        name = new_name_file(self.name, self.path)

        __f = open(self.path + '\\' + name, 'wb')

        return __f

    def __open_file_for_appending(self, is_binary):
        if is_binary:
            __f = open(self.path + '\\' + self.name, 'ab')
        else:
            __f = open(self.path + '\\' + self.name, 'at')

        return __f

    def __str__(self):
        # todo complete str of class file
        pass


class Node:

    def __init__(self, name: str, path: str, ip: str, port: int):
        self.name = name
        self.ip = ip
        self.path = path
        self.port = port

        self.lock = threading.Lock()
        self.folders = None
        self.node_list = {}

        # make folder
        self.__create_directory()

        self.tcp_server = TcpServer(self.folders['DOWNLOAD'], ip, port=0, name=name)
        self.udp_server = UdpServer(self.folders['DOWNLOAD'], self.node_list, self.lock,
                                    ip, port, self.tcp_server, name=name)

    def start_node(self):
        self.load_directory_in_node()
        if not self.tcp_server.isAlive():
            self.tcp_server.start()
        if not self.udp_server.isAlive():
            self.udp_server.start()

    def stop_node(self):
        if self.tcp_server.isAlive():
            self.tcp_server.stop()
        if self.udp_server.isAlive():
            self.udp_server.stop()

    def download_file(self, name: str):

        addr = self.udp_server.find_file(name)
        print(name, addr)

        if addr is not None:
            temp = download_file_from(name,
                                      self.tcp_server.host_info,
                                      addr,
                                      self.folders['DOWNLOAD'])

            state, name, path = temp
            if state:
                i = name.rfind('_', 0, len(name))
                main_name = name[:i]
                assemble_files(path, name, path, main_name, start_zero=True)
                # shutil.move(self.folders['TEMP'] + os.sep + main_name, path + os.sep + main_name)

            return state
        else:
            return False

    def load_directory_in_node(self):
        """
        dir_file.txt: 'name ip port' or 'name ip'
        :return:
        """
        file = self.folders['DIR'] + os.sep + 'dir_file.txt'
        self.lock.acquire()
        try:
            new_list = []
            dir_file = open(file, 'rt')

            lines = dir_file.readlines()
            for line in lines:
                line = line.split(' ')
                l = []
                for e in line:

                    l.append(e.strip(os.linesep))
                # name ip pn proxy_ip proxy_pn

                if len(l) == 2:
                    temp = AddressIp(l[1],
                                     self.port,
                                     None,
                                     None,
                                     l[0])
                    new_list.append(temp)
                elif len(l) == 3:
                    temp = AddressIp(l[1],
                                     int(l[2]),
                                     None,
                                     None,
                                     l[0])
                    new_list.append(temp)
                elif len(l) == 4:
                    temp = AddressIp(l[1],
                                     int(l[2]),
                                     l[3],
                                     None,
                                     l[0])
                    new_list.append(temp)
                elif len(l) == 5:
                    temp = AddressIp(l[1],
                                     int(l[2]),
                                     l[3],
                                     int(l[4]),
                                     l[0])
                    new_list.append(temp)
            dir_file.close()

            temp = []
            for i in new_list:
                temp.append((i.ip, i))

            self.node_list.update(dict(temp))

        except FileNotFoundError:
            print('there is not find dir_file.txt')
        except ValueError as v:
            dir_file.close()
            print('dir_file wasn\'t matched with format(<name> <ip> {}) {}'
                  .format('<proxy ip if it has proxy ip>', self.name))
            print(v)
        except Exception as err:
            print(err)
        self.lock.release()

    def distribute_discovery_message(self):
        self.lock.acquire()
        for addr in self.node_list.keys():

            des_server = self.node_list[addr]

            send, hub = is_there_next_des(self.udp_server.host_info, des_server)

            if send:
                # print(f'from {self.udp_server.host_info} send to {hub}')
                try:
                    send_directory_message_to(self.node_list,
                                              self.udp_server.host_info,
                                              des_server,
                                              hub)
                except socket.error:
                    print('[Error] distribute_discovery_message')

        self.lock.release()

    def get_state(self):
        text = f'[Node_{self.name}]:\n' \
            f'   [UDP Server]: alive:{self.udp_server.isAlive()} {self.udp_server.host_info}\n' \
            f'   [TCP Server]: alive:{self.tcp_server.isAlive()} {self.tcp_server.host_info}\n'
        node_list_txt = '   [nodelist]:'
        self.lock.acquire()
        values = self.node_list.values()
        self.lock.release()

        text += node_list_txt
        for i in values:
            text += '\n'
            text += ' ' * len(node_list_txt)
            text += f'{i}'
        return text

    def save_directory(self):
        file_name = 'dir_file.txt'
        file_addr = self.folders['DIR'] + os.sep + file_name

        self.lock.acquire()
        file_new_data = self.node_list.copy()
        self.lock.release()

        try:
            file = open(file_addr, 'wt')

            for i in file_new_data.values():
                line: AddressIp = i

                file.write(line.get_file_format() + '\n')

            file.close()

        except OSError:
            print('[Error] save_directory')

    def __create_directory(self):
        temp = self.path + os.sep + f'Node_{self.name}'
        os.makedirs(temp, exist_ok=True)

        temp = temp + os.sep

        os.makedirs(temp + 'download', exist_ok=True)
        os.makedirs(temp + 'dir_file', exist_ok=True)
        os.makedirs(temp + 'temp_data', exist_ok=True)
        self.folders = {'DOWNLOAD': temp + 'download',
                        'DIR': temp + 'dir_file',
                        'TEMP': temp + 'temp_data'}
        # print(self.folders)

    def __serialize_data(self, s_date):
        pass

    def __deserialize_data(self, s_data):
        pass

    def __chose_best(self):
        pass


class NetWolf:
    """
    This is main class of NetWolf project
    date: 6/8/2020
    author: Amirhosein Amir Firouzkouhi ( 9528007)
    """

    def __init__(self):
        print('NetWolf 1398-1399')

        self.prompt_info_and_create_node()

        self.node.start_node()

        self.is_running_distributing = True

        self.timer_for_distributing = threading.Thread(target=self.__distribute_nodes, args=[])
        self.timer_for_distributing.start()

        self.__start_user_command()

    def __start_user_command(self):
        prompt = 'start'

        while True:
            status_area = 'for exiting application type \'quit\'\n'
            status_area += self.node.get_state()
            print(status_area)
            sleep(0.2)
            prompt = input('line:')
            self.answer_command(prompt)
            if prompt == 'quit':
                self.is_running_distributing = False
                self.node.stop_node()
                break
            os.system('cls')

    def __distribute_nodes(self):
        while self.is_running_distributing:
            sleep(UDP_TIMER)
            self.node.distribute_discovery_message()

    def answer_command(self, prompt: str):

        prompt = prompt.strip(os.linesep + ' ').split(' ')
        world = []
        for i in prompt:
            if not len(i) == 0:
                world.append(i)

        commands = ['get', 'load']

        if len(world) == 2:
            if world[0] == commands[0]:
                print(self.node.download_file(world[1]))
        elif len(world) == 1:
            if world[0] == commands[1]:
                self.node.load_directory_in_node()
        else:
            print('wrong command')

    def prompt_info_and_create_node(self):

        def check_ip(temp_ip: str):
            temp_ip = temp_ip.strip(os.linesep + ' ')
            nums = temp_ip.split('.')

            if not len(nums) == 4:
                return False

            for i in nums:
                if int(i) > 255 or int(i) < 0:
                    return False

            return True

        ip = None
        port = 0
        path = ''
        name = ''
        is_entered_path = False
        is_entered_name = False
        err = ''
        # while True:
        #     try:
        #         port = int(input(f'{err}Please enter port number: '))
        #         err = ''
        #         if port < 0 or port > 2 ** 16:
        #             raise ValueError
        #         break
        #     except ValueError as value:
        #         # print(value)
        #         err = '[Your path is not correct] '
        #         clear_output()
        #         continue

        while True:
            try:
                if not is_entered_path:
                    path = input(f'{err}Please enter directory of list: ')
                    if os.path.exists(path):
                        err = ''
                        is_entered_path = True
                    else:
                        err = '[Your path is not correct] '
                        clear_output()
                        continue

                if not is_entered_name:
                    name = input(f'{err}Please enter your name: ')
                    # if os.path.exists(path + os.sep + name):
                    #     err = '[There is name like this]'
                    #     clear_output()
                    #     continue
                    # else:
                    #     is_entered_name = True
                    #     err = ''
                    is_entered_name = True
                    err = ''

                ip = input(f'{err}Please enter ip: ')
                if check_ip(ip):
                    err = ''
                    break
                else:
                    err = '[Your ip is not correct] '

            except ValueError as value:
                clear_output()
                # print(value)
                continue

        # while True:
        #     try:
        #         name = input(f'{err}Please enter your name: ')
        #         if os.path.exists(path + os.sep + name):
        #             err = '[There is name like this]'
        #             clear_output()
        #         else:
        #             break
        #     except ValueError as value:
        #         clear_output()
        #         # print(value)
        #         continue

        self.node = Node(name, path, ip, UDP_PORT_NUMBER)

    def __str__(self):
        return "Net wolf < version 1>"


class NotMatchFormat(Exception):

    def __str__(self):
        print('Format was not matched')


# end of classes
def prepare_directory_message(addr_dict: dict):
    """
    dict = { 'ip' : AddressIp(ip, portNum, proxy Ip, proxyPortNumber)}

    :param addr_dict:
    :return: str string format of directory message
    """
    res = []
    for key in addr_dict.keys():
        value: AddressIp = addr_dict[key]
        if value.__class__ is AddressIp:
            temp = '{ip}, {portNum}, {pip}, {ppn}, {name}'.format(ip=value.ip,
                                                                  portNum=value.pn,
                                                                  pip=value.proxy_ip,
                                                                  ppn=value.proxy_pn,
                                                                  name=value.name)
            res.append(temp)
        else:
            print('[Error] prepare_directory_message')

    return '|'.join(res)


def prepare_response_data(rsp_txt: str, rsp_raw_data: bytearray):
    """
    prepare response with 'text'+ bytes format
    :param rsp_txt: length of rsp_message must be less than 255
    :param rsp_raw_data:
    :return:
    """
    rsp_txt = bytearray(rsp_txt, ENCODE_MODE, ERROR_ENCODING)
    rsp_txt_size = int.to_bytes(len(rsp_txt), 1, 'big', signed=False)

    rsp_raw_data_size = len(rsp_raw_data)
    rsp_raw_data_size = int.to_bytes(rsp_raw_data_size, 3, 'big', signed=False)

    return bytearray(rsp_txt_size) + bytearray(rsp_raw_data_size) + rsp_txt + rsp_raw_data


def prepare_get_response(name: str, tcp_server_addr: AddressIp):
    """
    get_response: name + tcp_server_address
    :param name:
    :param tcp_server_addr:
    :return:
    """
    get_name = bytearray(name, ENCODE_MODE, ERROR_ENCODING)
    get_name_size = int.to_bytes(len(get_name), 1, 'big', signed=False)

    get_addr = tcp_server_addr.get_format()
    get_addr = bytearray(get_addr, ENCODE_MODE, ERROR_ENCODING)
    get_addr_size = int.to_bytes(len(get_addr), 1, 'big', signed=False)
    return bytearray(get_name_size) + bytearray(get_addr_size) + get_name + get_addr


def prepare_download_message_data(name: str):
    return bytearray(int.to_bytes(len(name), 2, 'big', signed=False)) \
            + bytearray(name, ENCODE_MODE, ERROR_ENCODING)


def prepare_list_of_files(list_of_files: list) -> bytearray:
    """
    prepare proper format.  ...|<name of file>|...
    :param list_of_files: list of name of files
    :return: bytearray: proper format
    """
    return bytearray('|'.join(list_of_files).encode(ENCODE_MODE, ERROR_ENCODING))


def send_message_to(mes: Message, next_des: tuple):
    """
    use udp protocol for sending message.
    :param mes: Message
    :param next_des: (IP, port number)
    :return: None
    """
    skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    skt.sendto(mes.get_data(), next_des)
    skt.close()


def send_message_to_get_file(name: str, src_server: AddressIp, des_server: AddressIp, next_des: tuple):
    mes = GetData(bytearray(name, ENCODE_MODE, ERROR_ENCODING), src_server, des_server)
    send_message_to(mes, next_des)


def send_directory_message_to(dir_dict: dict, src_server: AddressIp, des_server: AddressIp, next_des: tuple):
    """
    get a dictionary of ip: AddressIp, then prepare message and send to next hub
    :param dir_dict: dictionary of ip: AddressIp
    :param src_server: source server
    :param des_server: destination server
    :param next_des: next hub
    :return: None
    """
    mes = prepare_directory_message(dir_dict)
    mes_data = DirectoryData(bytearray(mes, ENCODE_MODE, ERROR_ENCODING), src_server, des_server)
    send_message_to(mes_data, next_des)


def send_response_message_to(rsp: bytearray, src_server: AddressIp, des_server: AddressIp, next_des: tuple):
    resp_data = ResponseData(rsp, src_server, des_server)
    send_message_to(resp_data, next_des)


def recv_data(skt: socket.socket, path: str):
    """
    receive files after getting SENDING_WAS_FINISHED response
    :param skt: socket.socket
    :param path: the path which file will be stored
    :return: state: boolean, name: file's name which is received
    stored_path: path that file is stored.
    """

    # To finish the loop
    running = True

    # get name in first sending
    first = True
    name = None

    # is_successful
    is_successful = True

    # what is stored path
    stored_path = None

    files = []
    while running:
        # extract message
        command, src_des, raw_data = extract_tcp_message(skt)

        if command == ResponseData.command:
            txt, file_data = extract_response_data(raw_data)
            if txt == SENDING_WAS_FINISHED:
                break
            elif txt == NOT_FOUND_RESPONSE_TEXT:
                is_successful = False
                break

            try:
                if first:
                    name = File(txt, path).save_data(file_data)
                    files.append(name)
                    point = name.rfind('\\', 0, len(name))
                    stored_path = name[:point]
                    name = name[1 + point:]
                    first = False
                else:
                    files.append(File(txt, path).save_data(file_data))
            except IOError:
                print('[Error] recv_data: IOError')
                is_successful = False
                name = None
                stored_path = None
                break
            except Exception:
                print('[Error] recv_data: Error')
                is_successful = False
                name = None
                stored_path = None
                break
        else:
            is_successful = False
            name = None
            stored_path = None
            break

    if not is_successful:
        for i in files:
            os.remove(i)

    return is_successful, name, stored_path


def download_file_from(name: str, src: AddressIp, des: AddressIp, path: str):
    """
    downloading files from tcp server
    :param name: name of requested file
    :param src: requester's address
    :param des: TCP server address which needed to download
    :param path: the path which file will be stored
    :return: state: boolean, name: received file's name,
    path: the path which file will be stored
    """
    res = (False, None, None)
    try:
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.connect((des.ip, des.pn))

        raw_data = prepare_download_message_data(name)
        download_mes = DownloadData(raw_data, src, des)

        skt.send(download_mes.get_data())

        cmd, src_des, temp_data = extract_tcp_message(skt)

        if not len(temp_data) == 0 and cmd == ResponseData.command:
            is_found, temp_data = extract_response_data(temp_data)

            if is_found == FOUND_RESPONSE_TEXT:
                res = recv_data(skt, path)

        skt.close()
    except socket.error as err:
        print(err)
        print('[Error] download_file_from: error in socket')

    return res


def extract_download_data(raw_data: bytearray):
    name_siz = int.from_bytes(raw_data[:2], 'big', signed=False)
    name = raw_data[2:name_siz + 2].decode(ENCODE_MODE, ERROR_ENCODING)
    return name


def extract_response_data(raw_data: bytearray):
    rsp_txt_size = raw_data[0]
    rsp_txt = raw_data[4:(rsp_txt_size + 4)].decode(ENCODE_MODE, ERROR_ENCODING)
    rsp_data = raw_data[rsp_txt_size + 4:]
    return rsp_txt, rsp_data


def extract_get_response_data(raw_data: bytearray):
    if not len(raw_data) == 0:
        rsp_name_size = raw_data[0]
        rsp_name = raw_data[2:rsp_name_size + 2].decode(ENCODE_MODE, ERROR_ENCODING)
        rsp_addr = extract_address_ip_format(raw_data[rsp_name_size + 2:])

        return rsp_name, rsp_addr[0]
    return None, None


def extract_list_of_files_data(raw_data: bytearray):
    # size_of_len_format = raw_data[0]
    # len_of_format = int.from_bytes(raw_data[1:size_of_len_format+1], 'big', signed=False)
    names = raw_data.decode(ENCODE_MODE, ERROR_ENCODING)
    names = names.split('|')
    return names


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


def is_there_next_des(base: AddressIp, des: AddressIp):
    if base.ip == des.ip:
        return False, (des.ip, des.pn)
    elif base.proxy_ip is None:
        if des.proxy_ip is None:
            return True, (des.ip, des.pn)
        else:
            return True, (des.proxy_ip, des.proxy_pn)
    else:
        if base.proxy_ip == des.proxy_ip:
            return True, (des.ip, des.pn)
        else:
            return True, (base.proxy_ip, base.proxy_pn)


def update_proxy_of_server(dir_dict: dict, node_ip: AddressIp):
    host = socket.gethostbyname(socket.gethostname())
    if not node_ip.ip == host:
        for addr in dir_dict.keys():
            value: AddressIp = dir_dict[addr]

            if host == value.ip:
                node_ip.proxy_ip = value.ip
                node_ip.proxy_pn = value.pn
            return

        node_ip.proxy_pn = None
        node_ip.proxy_pn = None


if __name__ == '__main__':
    NetWolf()
