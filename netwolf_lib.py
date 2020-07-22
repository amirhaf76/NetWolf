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
BRIDGE_MAKE = '<BRIDGE_MAKE>'

UDP_TIMER = 0.006
UDP_MESSAGE_SIZ = 500 * 100


class AddressIp:

    def __init__(self, ip, pn, proxy_ip, proxy_pn):
        self.ip = ip
        self.pn = pn
        self.proxy_ip = proxy_ip
        self.proxy_pn = proxy_pn

    def __str__(self):
        return (f'ip:{self.ip},' +
                f'pn:{self.pn},' +
                f'proxy_ip:{self.proxy_ip},' +
                f'proxy_pn:{self.proxy_pn}')

    def get_format(self):
        return (f'{self.ip}, ' +
                f'{self.pn}, ' +
                f'{self.proxy_ip}, ' +
                f'{self.proxy_pn}')

    def __eq__(self, o) -> bool:
        if o is None or not o.__class__ == self.__class__:
            return False
        thing: AddressIp = o
        return thing.ip == self.ip and \
               thing.pn == self.pn and \
               thing.proxy_ip == self.proxy_ip and \
               thing.proxy_pn == self.proxy_pn


# functions
def new_name_file(name: str, path: str):
    index = 0
    # Todo os.listdir raise exception FileNotFound
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
        if len(temp_list) == 4:
            ipp = None
            ppn = None

            if not temp_list[2].strip(' \'') == 'None':
                ipp = temp_list[2].strip(' \'')
            if not temp_list[3].strip(' \'') == 'None':
                ppn = int(temp_list[3])

            temp_address_ip = AddressIp(temp_list[0].strip(' \''),
                                        int(temp_list[1]),
                                        ipp,
                                        ppn)

            res.append(temp_address_ip)
        else:
            print(t)

            # Todo need exception
    return res


def extract_source_and_destination(raw_data: bytearray):
    if not len(raw_data) == 0:
        src_des = extract_address_ip_format(raw_data)
        dict_src_dec = {SRC: src_des[0],
                        DES: src_des[1]}
        return dict_src_dec
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


def filter_directory_dictionary(base_address_ip: AddressIp, src: AddressIp, dir_dict: dict):
    if dir_dict.__contains__(base_address_ip.ip):
        dir_dict.pop(base_address_ip.ip)
    dir_dict.update({src.ip: src})
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


# classes
class Server(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        self.__start_server()

    def __start_server(self):
        raise NotImplementedError("Subclass must implement this abstract method")


class TcpServer(Server):
    __pool = ThreadPoolExecutor(max_workers=5)
    __tcp_socket = None

    # its better to give it address of localhost
    def __init__(self, path: str, addr, port=0):
        Server.__init__(self)
        self.path = path
        self.host_info = AddressIp(addr, port, None, None)
        self.__is_end = False

    def run(self):
        self.__start_server()

    def stop(self):
        self.__is_end = True
        self.__tcp_socket.close()

    def __start_server(self):
        # get local address
        addr = self.host_info.ip
        port = self.host_info.pn
        if addr is None:
            addr = socket.gethostbyname(socket.gethostname())

        # create a socket
        self.__tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # bind a socket to the address and random port
        self.__tcp_socket.bind((addr, port))

        # save socket information
        ip, pn = self.__tcp_socket.getsockname()
        self.host_info = AddressIp(ip, pn, None, None)
        # start to listening
        self.__tcp_socket.listen(2)

        print('[TCP Server] Server has been started')
        print('[TCP Server] IP:{} port number:{} path:{}'.
              format(self.host_info.ip, self.host_info.pn, self.path))
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
        command, src_des, raw_data = extract_tcp_message(skt)
        print(raw_data)
        print('here')
        if command == ResponseData.command:
            name = extract_response_data(raw_data)
            print(name)
            if is_there_file(self.path, name):
                self.__send(name, src_des[DES], src_des[SRC])
            else:
                self.__response_not_found(name, src_des[DES], src_des[SRC])

        skt.close()

    def __send(self, name: str, src: AddressIp, des: AddressIp):

        size = get_byte_size_of_file(self.path, name)

        for part in range(size):
            # use get_ith_mb_from function
            data_file = get_ith_mb_from(self.path, name, part)

            rsp_data = prepare_response_data(f'{name}_part{part}', bytearray(data_file))
            rsp_mes = ResponseData(rsp_data, src, des)

            self.__tcp_socket.send(rsp_mes.get_data())

        # send final response
        self.__response_done(name, src, des)

    # Todo change txt response
    def __response_not_found(self, name, src: AddressIp, des: AddressIp):
        name = name.encode(ENCODE_MODE, ERROR_ENCODING)
        rsp_done = prepare_response_data(NOT_FOUND_RESPONSE_TEXT, bytearray(name))
        self.__tcp_socket.send(ResponseData(rsp_done, src, des).get_data())

    def __response_done(self, name, src: AddressIp, des: AddressIp):
        rsp_done = prepare_response_data(f'{SENDING_WAS_FINISHED}_{name}', bytearray(0))
        self.__tcp_socket.send(ResponseData(rsp_done, src, des).get_data())


class UdpServer(Server):
    # 1 Mib
    __size_of_message = 500 * 100
    __udp_socket = None

    def __init__(self, path: str,
                 dir_dict: dict,
                 dir_lock: threading.Lock,
                 ip, port, tcp_server: TcpServer = None):

        Server.__init__(self)
        self.path = path
        self.dis_dict = dir_dict
        self.dir_lock = dir_lock
        self.host_info = AddressIp(ip, port, None, None)
        self.__is_end = False

        self.__tcp_server = tcp_server

    def run(self):
        self.__start_server()

    def stop(self):
        self.__is_end = True
        self.__udp_socket.close()

    def __start_server(self):
        addr = self.host_info.ip
        port = self.host_info.pn
        if addr is None:
            addr = socket.gethostbyname(socket.gethostname())

        self.__udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__udp_socket.bind((addr, port))
        temp_tuple = self.__udp_socket.getsockname()
        self.host_info = AddressIp(temp_tuple[0],
                                   temp_tuple[1],
                                   self.host_info.proxy_ip,
                                   self.host_info.proxy_pn)

        print('[UDP Server] Server has been started')
        print('[UDP Server] IP:{} port number:{} path:{}'.
              format(self.host_info.proxy_ip, self.host_info.proxy_pn, self.path))

        while not self.__is_end:
            try:
                command, src_des, rec_data = extract_udp_message(self.__udp_socket)
                self.__client_handler(command, src_des, rec_data)
            except OSError:
                if self.__is_end:
                    print('[UDP Server] Server stop manually')
                else:
                    print(OSError)

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
                get_rsp = prepare_get_response(name, AddressIp('None', 0, 'None', 'None'))
            else:
                get_rsp = prepare_get_response(name, self.__tcp_server.host_info)

            # preparing response for sending file
            rsp = prepare_response_data(FOUND_RESPONSE_TEXT, get_rsp)

            # send data as an ResponseData
            send_response_message_to(rsp, self.host_info, src_des[SRC], next_des)
        else:
            # preparing response for sending file
            rsp = prepare_response_data(NOT_FOUND_RESPONSE_TEXT, bytearray(0))

            # send data as an ResponseData
            send_response_message_to(rsp, self.host_info, src_des[SRC], next_des)

    def __handle_directory_message(self, src_des: dict, rec_data: bytes):
        new_dir_dict = make_directory_dictionary(rec_data)
        new_dir_dict = filter_directory_dictionary(self.host_info, src_des[SRC], new_dir_dict)

        self.dir_lock.acquire()
        self.dis_dict.update(new_dir_dict)

        self.dis_dict.update(update_proxy_of_server(self.dis_dict, self.host_info))

        self.dir_lock.release()


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
               '             destination: {ias}, \n' \
               '                   proxy: {iad}\n' \
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
        Message.__init__(self, get_data, src, des)


class DownloadData(Message):
    command = 'DOWNLOAD'

    def __init__(self, dwn_data: bytearray, src: AddressIp, des: AddressIp):
        Message.__init__(self, dwn_data, src, des)


class ResponseData(Message):
    command = 'RSP'

    def __init__(self, rsp_data: bytearray, src: AddressIp, des: AddressIp):
        Message.__init__(self, rsp_data, src, des)


class DirectoryData(Message):
    # todo complete directory data, it needs to define its format
    command = 'DIR'

    def __init__(self, dir_data: bytearray, src: AddressIp, des: AddressIp):
        Message.__init__(self, dir_data, src, des)


class BridgeData(Message):
    # todo complete directory data, it needs to define its format
    command = 'BRG'

    def __init__(self, brg_data: bytearray, src: AddressIp, des: AddressIp):
        Message.__init__(self, brg_data, src, des)


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
            command, src_des, raw_data = extract_tcp_message(self.side2)

            if command == BridgeData.command:
                statue = raw_data.decode(ENCODE_MODE, ERROR_ENCODING)
                if statue == BRIDGE_CLOSE:
                    self.running = False

            mes = reassemble_mes(command, src_des, raw_data)
            self.side1.send(mes.get_data())

    def stop(self):
        self.running = False
        self.side1.close()


class File:
    def __init__(self, name, path):
        self.name = name
        self.path = path

    def save_data(self, data: bytearray):
        file = self.__open_file()

        file.write(data)

        temp = file.name

        file.close()
        return temp

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
    node_list = {}
    lock = threading.Lock()
    folders = None

    def __init__(self, name: str, path: str, ip: str, port: int):
        self.name = name
        self.ip = ip
        self.path = path
        self.port = port
        self.tcp_server = TcpServer(path, ip, port=0)
        self.udp_server = UdpServer(path, self.node_list, self.lock,
                                    ip, port, self.tcp_server)

        # make folder
        self.__create_directory()

        # prepare timer
        self.timer = threading.Timer(UDP_TIMER,
                                     self.__distribute_discovery_message,
                                     [self])

        # start timer, it's working in loop
        self.timer.start()

    def start_node(self):
        self.__load_directory_in_node()
        self.__start_tcp_server()
        self.__start_udp_server()

    def __start_tcp_server(self):
        self.tcp_server.start()

    def __start_udp_server(self):
        self.udp_server.start()

    def download_file(self, name: str, addr: AddressIp):
        state, name, path = download_file_from(name,
                                               self.tcp_server.host_info,
                                               addr,
                                               self.path + os.sep + 'download')
        i = name.rfind('_', 0, len(name))
        main_name = name[:i]
        assemble_files(path, name, path, main_name, start_zero=True)

    def __load_directory_in_node(self):
        dir_folder = self.folders['DIR']
        try:
            new_list = []
            dir_file = open(dir_folder, 'rt')
            lines = dir_file.readlines()
            for l in lines:
                l = l.split(' ')
                if len(l) == 2:
                    temp = AddressIp(l[1],
                                     self.port,
                                     None,
                                     None)
                    new_list.append(temp)
                elif len(l) == 3:
                    temp = AddressIp(l[1],
                                     self.port,
                                     l[1],
                                     self.port)
                    new_list.append(temp)
            dir_file.close()

            temp = []
            for i in new_list:
                temp.append((i.ip, i))

            self.node_list = dict(temp)

        except FileNotFoundError:
            return 'We can\'t find dir_file.txt'
        except ValueError:
            return 'dir_file wasn\'t matched with format(<name> <ip> {})'.format('<proxy ip if it has proxy ip>')

        return None

    def __create_directory(self):
        self.path = self.path + os.sep + 'NetWolf'
        os.makedirs(self.path, exist_ok=True)

        temp = self.path + os.sep

        os.makedirs(temp + 'download', exist_ok=True)
        os.makedirs(temp + 'dir_file', exist_ok=True)
        self.folders = {'DOWNLOAD': temp + 'download',
                        'DIR': temp + 'dir_file'}

    def __distribute_discovery_message(self):
        for addr in self.node_list.keys():

            des_server = self.node_list[addr]

            send, hub = is_there_next_des(self.udp_server.host_info, des_server)

            if send:
                send_directory_message_to(self.node_list,
                                          self.udp_server.host_info,
                                          des_server,
                                          hub)
        self.timer.start()

    def __create_response_message(self):
        pass

    def __start_timer(self, discovery):
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
    dict = { 'ip' : AddressIp(ip, portNum, proxy Ip, proxyPortNumber)}

    :param addr_dict:
    :return: str string format of directory message
    """
    res = []
    for key in addr_dict.keys():
        value: AddressIp = addr_dict[key]
        if value.__class__ is AddressIp:
            temp = '{ip}, {portNum}, {pip}, {ppn}'.format(ip=value.ip,
                                                          portNum=value.pn,
                                                          pip=value.proxy_ip,
                                                          ppn=value.proxy_pn)
            res.append(temp)
        else:
            return 'error in prepare_directory_message'
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
    # print(log2(rsp_raw_data_size))
    # print(ceil(log2(rsp_raw_data_size)))
    rsp_raw_data_size = int.to_bytes(rsp_raw_data_size, 3, 'big', signed=False)

    return bytearray(rsp_txt_size) + bytearray(rsp_raw_data_size) + rsp_txt + rsp_raw_data


def prepare_get_response(name: str, tcp_server_addr: AddressIp):
    """
    its not suitable!!!!!!!
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
    name doesn't work for while!!!!!. receive files after getting SENDING_WAS_FINISHED response
    :param skt: socket.socket
    :param path: the path which file will be stored
    :return: state: boolean, name: file's name which is received
    stored_path: path that file is stored.
    """
    running = True
    first = True
    name = None
    stored_path = None
    state = True
    while running:
        command, src_des, raw_data = extract_tcp_message(skt)
        if command == ResponseData.command:
            txt, file_data = extract_response_data(raw_data)
            if txt == SENDING_WAS_FINISHED:
                break
            elif txt == NOT_FOUND_RESPONSE_TEXT:
                state = False
                break
            if first:
                name = File(txt, path).save_data(file_data)
                point = name.rfind('\\', 0, len(name))
                stored_path = name[:point]
                name = name[1 + point:]
                first = False
            else:
                File(txt, path).save_data(file_data)

    return state, name, stored_path


def download_file_from(name: str, src: AddressIp, des: AddressIp, save_in: str):
    """
    downloading files from tcp server
    :param name: name of requested file
    :param src: requester's address
    :param des: TCP server address which needed to download
    :param save_in: the path which file will be stored
    :return: state: boolean, name: received file's name,
    path: the path which file will be stored
    """
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    raw_data = bytearray([len(name)]) + bytearray(name, ENCODE_MODE, ERROR_ENCODING)
    download_mes = DownloadData(raw_data, src, des)

    skt.connect((src.ip, src.pn))
    skt.send(download_mes.get_data())

    temp = recv_data(skt, save_in)
    skt.close()
    return temp


def extract_download_data(raw_data: bytearray):
    name_siz = raw_data[0]
    name = raw_data[1:name_siz + 1].decode(ENCODE_MODE, ERROR_ENCODING)
    return name


def extract_response_data(raw_data: bytearray):
    rsp_txt_size = raw_data[0]
    # rsp_data_size = raw_data[1]
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
    for addr in dir_dict.keys():
        value: AddressIp = dir_dict[addr]

        if host == value.ip:
            node_ip.proxy_ip = value.ip
            node_ip.proxy_pn = value.pn

    return dir_dict
