import netwolf_lib as nfb
import unittest as ut
import os
import socket
import threading
from time import sleep
from math import ceil

LIST_TEST_PATH = ['F:', 'Amir', 'University', 'Computer Network', 'Project', 'NetWolf', 'Test']
LIST_BASE_FILES_PATH = ['F:', 'Amir', 'University', 'Computer Network', 'Project', 'NetWolf', 'Files_for_testing']

TEST_PATH = f'{os.sep}'.join(LIST_TEST_PATH)
BASE_FILES_PATH = f'{os.sep}'.join(LIST_BASE_FILES_PATH)

IP = socket.gethostbyname(socket.gethostname())

TEST_FILE_NAME = {'MUSIC': 'Awaken.mp3', 'PICTURE': 'BACKGROUND FULL HD (5).JPG'}
TEST_SRC = nfb.AddressIp('127.0.0.5', 2000, '192.168.0.2', 5000)
TEST_DES = nfb.AddressIp('127.0.0.8', 2000, '192.168.0.2', 5000)


def check_two_file(path1: str, name1: str, path2: str, name2: str):
    siz1 = nfb.get_byte_size_of_file(path1, name1)
    siz2 = nfb.get_byte_size_of_file(path2, name2)

    if not siz1 == siz2:
        return False

    for part in range(siz1):
        temp1 = nfb.get_ith_mb_from(path1, name1, part)
        temp2 = nfb.get_ith_mb_from(path2, name2, part)
        if not temp1 == temp2:
            return False
    return True


class TestTcpServer(ut.TestCase):
    path = TEST_PATH + os.sep + 'TestTcpServer'
    client = nfb.AddressIp('127.0.0.16', 4433, None, None)
    tcp = nfb.TcpServer(TEST_PATH, IP)
    file = 'File'

    def test_start_and_stop(self):
        self.tcp.start()
        sleep(2)
        self.tcp.stop()
        sleep(1)

    def download_file(self, name):
        # Todo the problem is DownloadData, because its text doesn't have size
        name = name.encode(nfb.ENCODE_MODE,
                           nfb.ERROR_ENCODING)
        dn = nfb.prepare_response_data(bytearray(name),
                              self.client,
                              self.tcp.host_info)
        print(dn.get_data())
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # skt.bind((self.client.ip, self.client.pn))

        # print(self.client)
        # print(self.tcp.host_info)
        skt.connect((self.tcp.host_info.ip, self.tcp.host_info.pn))
        skt.send(dn.get_data())

        cmd, src_des, temp_data = nfb.extract_tcp_message(skt)
        self.assertEqual(nfb.ResponseData.command, cmd)
        self.assertDictEqual({nfb.SRC: self.tcp.host_info,
                              nfb.DES: self.client}, src_des)
        txt, temp_data = nfb.extract_response_data(temp_data)
        self.assertEqual(nfb.NOT_FOUND_RESPONSE_TEXT, txt)
        self.assertEqual(self.file, temp_data)

        skt.close()

    def test_response_not_found(self):
        self.tcp.start()
        sleep(1)
        self.download_file(self.file)

        self.tcp.stop()


class TestUdpServer(ut.TestCase):
    tcp = nfb.TcpServer(TEST_PATH + os.sep + 'TestUcpServer', '127.0.0.44')
    client = nfb.AddressIp('127.0.1.16', 4433, None, None)
    dict_list = {}
    udp = nfb.UdpServer(TEST_PATH + os.sep + 'TestUcpServer',
                        dict_list,
                        threading.Lock(),
                        '127.0.0.44',
                        4433,
                        tcp)

    def test_start_and_stop(self):
        self.udp.start()
        sleep(2)
        self.udp.stop()
        sleep(1)

    def client_get_message(self):
        pass

    def client_server(self):
        nfb.send_message_to_get_file('hello.txt',
                                     self.client,
                                     self.udp.host_info,
                                     (self.udp.host_info.ip, self.udp.host_info.pn))

        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.bind((self.client.ip, self.client.pn))

        cmd, src_des, temp_data = nfb.extract_udp_message(skt)
        self.assertEqual(nfb.ResponseData.command, cmd)
        txt, temp_data = nfb.extract_response_data(temp_data)
        name, temp_data = nfb.extract_get_response_data(temp_data)

        self.assertEqual(nfb.NOT_FOUND_RESPONSE_TEXT, txt)
        self.assertIsNone(temp_data)
        self.assertIsNone(name)

        existence_file = 'BACKGROUND FULL HD (5).JPG'
        nfb.send_message_to_get_file(existence_file,
                                     self.client,
                                     self.udp.host_info,
                                     (self.udp.host_info.ip, self.udp.host_info.pn))

        cmd, src_des, temp_data = nfb.extract_udp_message(skt)
        self.assertEqual(nfb.ResponseData.command, cmd)
        txt, temp_data = nfb.extract_response_data(temp_data)
        name, temp_data = nfb.extract_get_response_data(temp_data)

        self.assertEqual(nfb.FOUND_RESPONSE_TEXT, txt)
        self.assertEqual(self.tcp.host_info, temp_data)
        self.assertEqual(existence_file, name)
        skt.close()

    def client_discovery(self):
        src = nfb.AddressIp('127.0.1.16', 4433, None, None)
        addr = [nfb.AddressIp(IP, 4000, None, None),
                nfb.AddressIp('127.0.1.24', 2545, None, None),
                self.udp.host_info]

        dict_temp = {'127.0.1.125': addr[0],
                     '127.0.1.24': addr[1],
                     self.udp.host_info.ip: addr[2]}

        send, hub = nfb.is_there_next_des(src, self.udp.host_info)

        nfb.send_directory_message_to(dict_temp,
                                      src,
                                      self.udp.host_info,
                                      hub)

    def test_discovery(self):
        self.udp.start()

        self.client_discovery()

        src = nfb.AddressIp('127.0.1.16', 4433, None, None)
        addr = [nfb.AddressIp(IP, 4000, None, None),
                nfb.AddressIp('127.0.1.24', 2545, None, None),
                self.udp.host_info]

        dict_temp = {IP: addr[0],
                     '127.0.1.24': addr[1],
                     '127.0.1.16': src}
        sleep(1)
        self.assertDictEqual(dict_temp, self.udp.dis_dict)
        temp_udp_address = nfb.AddressIp(self.udp.host_info.ip,
                                         self.udp.host_info.pn,
                                         IP,
                                         4000)
        self.assertTrue(temp_udp_address.__eq__(self.udp.host_info))
        self.udp.stop()

    def test_get_message_handler(self):
        self.udp.start()

        self.client_server()

        self.udp.stop()


class TestFilesFunction(ut.TestCase):

    def test_separating_and_saving_data(self):
        """
        test separate_to_mb and File.save_list_of_data
        :return:
        """
        path = TEST_PATH + os.sep + 'separating_and_saving_files'

        file1 = open(BASE_FILES_PATH + os.sep +
                     TEST_FILE_NAME['MUSIC'], 'rb')

        file2 = nfb.File('test_saving_data.mp3', path)

        datafile = bytearray(file1.read())
        file2.save_list_of_data(nfb.separate_to_mb(datafile))

        file2 = open(path + os.sep + 'test_saving_data.mp3', 'rb')
        self.assertEqual(file1.seek(0, 2), file2.seek(0, 2))

        temp = check_two_file(path,
                              'test_saving_data.mp3',
                              BASE_FILES_PATH,
                              TEST_FILE_NAME['MUSIC'])
        self.assertTrue(temp, 'Error in test_separating_and_saving_data')
        file2.close()
        file1.close()


class TestAllKindMessage(ut.TestCase):
    """
    test all kind of messages
    """

    def test_messages(self):
        self.test_dir_message()
        self.test_get_message()
        self.test_res_message()

    def test_get_message(self):
        arr = bytearray(list(range(0, 200)))
        mes = nfb.GetData(arr, TEST_SRC, TEST_DES)
        res = mes.get_data()
        res = res[(len(mes.command) + len(TEST_SRC.get_format()) + len(TEST_DES.get_format()) + 5):]
        self.assertListEqual([res], [res])
        self.assertEqual(mes.command, nfb.GetData.command)

    def test_dir_message(self):
        arr = bytearray(list(range(0, 200)))
        mes = nfb.DirectoryData(arr, TEST_SRC, TEST_DES)
        res = mes.get_data()
        res = res[(len(mes.command) + len(TEST_SRC.get_format()) + len(TEST_DES.get_format()) + 5):]
        self.assertListEqual([res], [res])
        self.assertEqual(mes.command, nfb.DirectoryData.command)

    def test_res_message(self):
        arr = bytearray(list(range(0, 200)))
        mes = nfb.ResponseData(arr, TEST_SRC, TEST_DES)
        res = mes.get_data()
        res = res[(len(mes.command) + len(TEST_SRC.get_format()) + len(TEST_DES.get_format()) + 5):]
        self.assertListEqual([res], [res])
        self.assertEqual(mes.command, nfb.ResponseData.command)


class TestFunctions(ut.TestCase):
    test_address_list = [nfb.AddressIp('amir', 232, 'io3232', 54645),
                         nfb.AddressIp('ali', 545, None, None)]
    test_address_dict = {test_address_list[0].ip: test_address_list[0],
                         test_address_list[1].ip: test_address_list[1]}
    test_address_str = " 'amir' , 232, 'io3232', 54645 | 'ali', 545, 'None', 'None'"
    test_address_encoded = test_address_str.encode(nfb.ENCODE_MODE, nfb.ERROR_ENCODING)
    test_src_des_str = " 'amir' , 232, 'io3232', 54645 | 'ali', 545, 'None', 'None'"
    test_src_des_encoded = test_src_des_str.encode(nfb.ENCODE_MODE, nfb.ERROR_ENCODING)
    test_address_src_des_dict = {nfb.SRC: test_address_list[0],
                                 nfb.DES: test_address_list[1]}

    def test_get_size_of_file(self):
        size = ceil(7902383 / (10 ** 6))
        file_size = nfb.get_byte_size_of_file(BASE_FILES_PATH, 'Awaken.mp3')
        self.assertEqual(size, file_size, msg='Error in test_get_size_of_file')

    def test_get_ith_mb_from(self):
        name = 'download'
        path = TEST_PATH + os.sep + self.test_get_ith_mb_from.__name__

        des = nfb.File(name, path)

        size = nfb.get_byte_size_of_file(BASE_FILES_PATH, TEST_FILE_NAME['MUSIC'])

        for i in range(size):
            temp_data = nfb.get_ith_mb_from(BASE_FILES_PATH, TEST_FILE_NAME['MUSIC'], i)
            des.save_data(temp_data)

        self.assertTrue(len(os.listdir(path)), size)

    def test_assemble_files(self):
        name = 'download'
        new_name = 'music.mp3'
        path = TEST_PATH + os.sep + self.test_assemble_files.__name__

        des = nfb.File(name, path)

        size = nfb.get_byte_size_of_file(BASE_FILES_PATH, TEST_FILE_NAME['MUSIC'])

        for i in range(size):
            temp_data = nfb.get_ith_mb_from(BASE_FILES_PATH, TEST_FILE_NAME['MUSIC'], i)
            des.save_data(temp_data)

        nfb.assemble_files(path,
                           name,
                           path,
                           new_name)
        self.assertTrue(check_two_file(path,
                                       new_name,
                                       BASE_FILES_PATH,
                                       TEST_FILE_NAME['MUSIC']))

    def test_extract_address_ip_format(self):
        test_list = nfb.extract_address_ip_format(self.test_address_encoded)
        self.assertListEqual(test_list, self.test_address_list)

    def test_extract_source_and_destination(self):
        test_dict = nfb.extract_source_and_destination(bytearray(self.test_address_encoded))
        self.assertDictEqual(test_dict, self.test_address_src_des_dict)

    def test_make_directory_dictionary(self):

        temp = (self.test_address_str.encode('utf-8', 'ignore'))
        temp_res = nfb.make_directory_dictionary(temp)

        self.assertDictEqual(temp_res, self.test_address_dict)

        test_list = " 'amir' , 232, 'io3232', 546,45 | 'ali', 545, 'None', 'None'"
        temp = (test_list.encode('utf-8', 'ignore'))

        try:
            temp_res = nfb.make_directory_dictionary(temp)
            self.assertNotEqual(temp_res, self.test_address_dict)
        except nfb.NotMatchFormat:
            pass

    def test_filter_directory_dictionary(self):
        d = nfb.filter_directory_dictionary(self.test_address_list[1],
                                            self.test_address_list[0],
                                            self.test_address_dict)
        self.assertDictEqual({self.test_address_list[0].ip: self.test_address_list[0]},
                             d)

    def test_prepare_directory_message(self):
        test = {'amir': nfb.AddressIp('amir', 232, 'io3232', 54645),
                'ali': nfb.AddressIp('ali', 545, None, None)}
        test_str = '{ip}, {portNum}, {ipp}, {ppn}|{ip1}, {portNum1}, {ipp1}, {ppn1}'.format(
            ip='amir',
            portNum=232,
            ipp='io3232',
            ppn=54645,
            ip1='ali',
            portNum1=545,
            ipp1=None,
            ppn1=None
        )
        mes = nfb.prepare_directory_message(test)
        self.assertEqual(mes, test_str)

    def test_extract_response_data(self):
        test_mes = b'\x0A\x00\x00\x02h123456789\x12\x34'
        txt, raw_data = nfb.extract_response_data(bytearray(test_mes))
        self.assertEqual(txt, 'h123456789')
        self.assertEqual(raw_data, b'\x12\x34')

    def test_prepare_response_data(self):
        test_txt = '<TEST>'
        test_data = bytearray(b'\x12\x74')
        test_message = nfb.prepare_response_data(test_txt, test_data)

        test_data = b'\x06\x00\x00\x02<TEST>\x12\x74'

        self.assertEqual(test_message, test_data)

    def test_prepare_get_response(self):
        test_txt = '<TEST>'
        test_message = nfb.prepare_get_response(test_txt, TEST_SRC)
        temp1 = test_txt.encode(nfb.ENCODE_MODE, nfb.ERROR_ENCODING)
        temp2 = TEST_SRC.get_format().encode(nfb.ENCODE_MODE, nfb.ERROR_ENCODING)
        test_data = bytearray([len(test_txt), len(TEST_SRC.get_format())]) + temp1 + temp2

        self.assertEqual(test_data, test_message)

    def test_extract_download_data(self):
        name = '<DOWNLOAD>'
        name_len = int.to_bytes(len(name),
                                1,
                                'big',
                                signed=False)
        dd = bytearray(name_len) + name.encode(nfb.ENCODE_MODE, nfb.ERROR_ENCODING)

        self.assertEqual(name, nfb.extract_download_data(dd))

    def test_update_proxy_of_server(self):
        addr = [nfb.AddressIp(IP, 4000, None, None),
                nfb.AddressIp('127.0.1.24', 2545, None, None)]
        node_ip = nfb.AddressIp('my ip', 200, None, None)

        dict_temp = {IP: addr[0],
                     '127.0.1.24': addr[1]}
        nfb.update_proxy_of_server(dict_temp, node_ip)
        self.assertTrue(node_ip.__eq__(nfb.AddressIp('my ip', 200, IP, 4000)))


class TestSocketFunction(ut.TestCase):
    address = socket.gethostbyname(socket.gethostname())

    # udp
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server_port = 6000
    udp_client_port = 6010

    # tcp
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    tcp_server_port = 4000
    tcp_client_port = 4010

    udp_address_list = [nfb.AddressIp(address, udp_server_port, None, None),
                        nfb.AddressIp('127.0.0.5', udp_client_port, None, None)]
    udp_address_src_des_dict = {nfb.SRC: udp_address_list[1],
                                nfb.DES: udp_address_list[0]}
    tcp_address_list = [nfb.AddressIp(address, tcp_server_port, None, None),
                        nfb.AddressIp('127.0.1.5', tcp_client_port, None, None)]
    tcp_address_src_des_dict = {nfb.SRC: tcp_address_list[0],
                                nfb.DES: tcp_address_list[1]}

    test_txt = '<TEST>'
    test_udp_data = bytearray(b'\x12\x34')
    test_tcp_data = bytearray(list((2 ** x) - 1 for x in range(1, 9)))

    def initialize_tcp_server(self):
        self.tcp_server.bind((self.address, self.tcp_server_port))

    def initialize_udp_server(self):
        self.udp_server.bind((self.address, self.udp_server_port))

    def start_listening(self):
        self.tcp_server.listen(3)

        s, t = self.tcp_server.accept()

        mes = nfb.Message(self.test_tcp_data,
                          self.tcp_address_src_des_dict[nfb.SRC],
                          self.tcp_address_src_des_dict[nfb.DES])
        s.send(mes.get_data())

        s.close()
        self.tcp_server.close()

    def test_initialize(self):
        self.initialize_udp_server()
        self.initialize_tcp_server()

    def test_extract_udp_message(self):
        self.initialize_udp_server()

        temp_mes = nfb.prepare_response_data(self.test_txt, self.test_udp_data)
        self.test_message = nfb.ResponseData(temp_mes,
                                             self.udp_address_list[1],
                                             self.udp_address_list[0])
        s_data = self.test_message.get_data() + bytearray(500 * 100 - len(self.test_message.get_data()))
        self.udp_client.sendto(s_data,
                               (self.address,
                                self.udp_server_port))

        command, src_des, raw_data = nfb.extract_udp_message(self.udp_server)

        self.assertEqual(command, nfb.ResponseData.command)
        self.assertDictEqual(src_des, self.udp_address_src_des_dict)

        txt, b_data = nfb.extract_response_data(raw_data)
        self.assertEqual(txt, self.test_txt)
        self.assertEqual(b_data, self.test_udp_data)

        self.udp_server.close()
        self.udp_client.close()

    def test_extract_tcp_message(self):
        self.initialize_tcp_server()
        t = threading.Thread(target=self.start_listening)
        t.start()

        sleep(1)

        server = self.tcp_address_src_des_dict[nfb.SRC]

        self.tcp_client.connect((server.ip, server.pn))

        command, src_des, temp_data = nfb.extract_tcp_message(self.tcp_client)

        self.assertEqual(nfb.Message.command, command)
        self.assertDictEqual(self.tcp_address_src_des_dict, src_des)
        self.assertEqual(self.test_tcp_data, temp_data)

        self.tcp_client.close()


class TestDownload(ut.TestCase):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_port = 40000
    server_ip = '127.0.0.5'
    path = BASE_FILES_PATH
    file = TEST_FILE_NAME['MUSIC']
    client = nfb.AddressIp('127.0.0.9', 12546, None, None)

    def run_server(self, name=None):
        self.server.bind((self.server_ip, self.server_port))
        self.server.listen(3)
        s, p = self.server.accept()

        siz = nfb.get_byte_size_of_file(self.path, self.file)

        send = True
        if name is not None:
            command, src_des, temp_data = nfb.extract_tcp_message(s)
            self.assertEqual(nfb.DownloadData.command, command)
            name = nfb.extract_download_data(temp_data)
            if not self.file == name:
                send = False

        if send:
            for i in range(siz):
                temp = nfb.get_ith_mb_from(self.path, self.file, i)

                rsp_data = nfb.prepare_response_data(f'{self.file}_part{i}', temp)
                rsp_mes = nfb.ResponseData(rsp_data, nfb.AddressIp(self.server_ip,
                                                                   self.server_port,
                                                                   None, None),
                                           self.client)
                s.send(rsp_mes.get_data())

            rsp_done = nfb.prepare_response_data(f'{nfb.SENDING_WAS_FINISHED}',
                                                 bytearray(2))

            s.send(nfb.ResponseData(rsp_done,
                                    nfb.AddressIp(self.server_ip,
                                                  self.server_port,
                                                  None,
                                                  None),
                                    nfb.AddressIp('127.0.0.9',
                                                  12546,
                                                  None,
                                                  None)
                                    ).get_data()
                   )
        sleep(2)
        s.close()
        self.server.close()

    def test_recv_data(self):
        t = threading.Thread(target=self.run_server)
        t.start()
        sleep(1)
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.connect((self.server_ip, self.server_port))

        state, name, path = nfb.recv_data(skt,
                                          TEST_PATH + os.sep + 'test_recv_data')

        skt.close()
        i = name.rfind('_', 0, len(name))
        main_name = name[:i]
        nfb.assemble_files(path, name, path, main_name, start_zero=True)
        self.assertTrue(state)

    def test_download_file_from(self):
        t = threading.Thread(target=self.run_server)
        t.start()
        sleep(1)

        server = nfb.AddressIp(self.server_ip, self.server_port, None, None)
        state, name, path = nfb.download_file_from(self.file,
                                                   server,
                                                   self.client,
                                                   TEST_PATH + os.sep + 'test_download_file_from')
        self.assertTrue(state)
        self.assertEqual(self.file + '_part0', name)
        self.assertTrue(name in os.listdir(TEST_PATH + os.sep + 'test_download_file_from'))

        i = name.rfind('_', 0, len(name))
        main_name = name[:i]
        nfb.assemble_files(path, name, path, main_name, start_zero=True)
