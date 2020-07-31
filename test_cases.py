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


class TestNetWolf(ut.TestCase):

    def test_initialize(self):
        nfb.NetWolf()

    def test_download(self):
        path = TEST_PATH + os.sep + 'TestNetWolf'
        node = nfb.Node('hello', path, '127.0.2.1', nfb.UDP_PORT_NUMBER)
        node.start_node()
        sleep(1)
        nfb.NetWolf()
        node.stop_node()

    def test(self):
        src = nfb.AddressIp('127.0.5.1', 15423, None, None)
        des = nfb.AddressIp('127.0.5.9', 15423, None, None)
        nfb.send_message_to(nfb.Message(bytearray(b'\x55'), src, des), ('127.0.0.98', 12054))


class TestNode(ut.TestCase):
    path = TEST_PATH + os.sep + 'TestNode'

    node1 = nfb.Node('node1', path, IP, 12345)
    node2 = nfb.Node('node2', path, '127.0.1.15', 54321)

    def test_initialize(self):
        nodes = os.listdir(self.node1.path)
        self.assertEqual(2, len(nodes))
        self.assertEqual(['Node_node1', 'Node_node2'], nodes)

    def test_start_stop(self):
        self.node1.start_node()
        print(self.node1.get_state())
        sleep(1)
        self.node1.stop_node()

    def test_load_directory_in_node(self):
        self.node1.load_directory_in_node()
        temp = self.node1.node_list
        for i in temp.keys():
            print(f'{i}  {temp[i]}')

    def test_distribute(self):
        self.node1.start_node()
        self.node2.start_node()
        sleep(0.2)
        print(self.node1.get_state())
        print(self.node2.get_state())
        self.node1.distribute_discovery_message()
        self.node2.distribute_discovery_message()
        self.node1.stop_node()
        self.node2.stop_node()
        sleep(1)
        print(self.node1.get_state())
        print(self.node2.get_state())

    def test_save_directory(self):
        self.node1.start_node()
        self.node2.start_node()
        self.node1.distribute_discovery_message()
        sleep(1)
        print(self.node1.get_state())
        print(self.node2.get_state())
        self.node2.save_directory()

        self.node1.stop_node()
        self.node2.stop_node()

    def test_download_file(self):
        self.node1.start_node()
        self.node2.start_node()
        sleep(0.2)
        self.node1.distribute_discovery_message()
        self.node2.distribute_discovery_message()
        sleep(1)
        print(self.node1.get_state())
        print(self.node2.get_state())
        print(self.node1.download_file('Awaken.mp3'))
        sleep(1)
        print(self.node2.download_file('BACKGROUND FULL HD (5).JPG'))
        sleep(.5)
        print(self.node1.download_file('Aw4aken.mp3'))
        self.node2.stop_node()
        self.node1.stop_node()


class TestTcpServer(ut.TestCase):
    path = TEST_PATH + os.sep + 'TestTcpServer'
    client = nfb.AddressIp('127.0.0.16', 4433, None, None)
    tcp = nfb.TcpServer(path, IP)
    file = 'File'

    def test_start_and_stop(self):
        self.tcp.start()
        sleep(2)
        self.tcp.stop()
        sleep(1)

    def download_file(self, name, isfile):

        dn = nfb.prepare_download_message_data(name)
        dn = nfb.DownloadData(dn, self.client, self.tcp.host_info)

        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        skt.connect((self.tcp.host_info.ip, self.tcp.host_info.pn))
        skt.send(dn.get_data())

        cmd, src_des, temp_data = nfb.extract_tcp_message(skt)
        if isfile:
            self.assertEqual(nfb.ResponseData.command, cmd)
            self.assertDictEqual({nfb.SRC: self.tcp.host_info,
                                  nfb.DES: self.client}, src_des)
            txt, temp_data = nfb.extract_response_data(temp_data)
            temp_dict = nfb.extract_get_response_data(temp_data)
            self.assertEqual(nfb.FOUND_RESPONSE_TEXT, txt)
            self.assertEqual(name, temp_dict['name'])
            nfb.recv_data(skt, self.tcp.path)

        else:
            self.assertEqual(nfb.ResponseData.command, cmd)
            self.assertDictEqual({nfb.SRC: self.tcp.host_info,
                                  nfb.DES: self.client}, src_des)
            txt, temp_data = nfb.extract_response_data(temp_data)
            print(temp_data)
            temp_dict = nfb.extract_get_response_data(temp_data)
            self.assertEqual(nfb.NOT_FOUND_RESPONSE_TEXT, txt)
            self.assertEqual(name, temp_dict['name'])

        skt.close()

    def test_response(self):
        self.tcp.start()
        sleep(1)
        self.download_file(self.file, False)
        sleep(1)
        name = 'BACKGROUND FULL HD (5).JPG'
        self.download_file(name, True)
        sleep(0.2)
        self.tcp.stop()

    def test_download(self):
        self.tcp.start()
        name = 'BACKGROUND FULL HD (5).JPG'
        sleep(0.2)
        temp = nfb.download_file_from(name,
                                      self.tcp.host_info,
                                      self.tcp.host_info,
                                      self.tcp.path + os.sep + 'test_download')
        self.assertTrue(temp[0])
        self.assertEqual('F:\\Amir\\University\\Computer Network\\Project\\NetWolf\\Test\\TestTcpServer\\test_download',
                         temp[2])
        self.tcp.stop()


class TestUdpServer(ut.TestCase):
    server_ip = '127.0.1.16'
    server_port = 48856

    tcp = nfb.TcpServer(TEST_PATH + os.sep + 'TestTcpServer', server_ip)
    client = nfb.AddressIp('127.0.1.14', 44533, None, None)
    dict_list = {}
    udp = nfb.UdpServer(TEST_PATH + os.sep + 'TestUdpServer',
                        dict_list,
                        threading.Lock(),
                        server_ip,
                        server_port,
                        tcp)

    def test_start_and_stop(self):
        self.udp.start()
        sleep(2)
        self.udp.stop()
        sleep(1)

    def client_server(self):
        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.bind((self.client.ip, self.client.pn))

        nfb.send_message_to_get_file('hello.txt',
                                     self.client,
                                     self.udp.host_info,
                                     (self.udp.host_info.ip, self.udp.host_info.pn))

        existence_file = 'BACKGROUND FULL HD (5).JPG'
        nfb.send_message_to_get_file(existence_file,
                                     self.client,
                                     self.udp.host_info,
                                     (self.udp.host_info.ip, self.udp.host_info.pn))

        nfb.send_message_to_get_file('Test.txt',
                                     self.client,
                                     self.udp.host_info,
                                     (self.udp.host_info.ip, self.udp.host_info.pn))

        cmd, src_des, temp_data = nfb.extract_udp_message(skt)
        self.assertEqual(nfb.ResponseData.command, cmd)
        txt, temp_data = nfb.extract_response_data(temp_data)
        temp_dict = nfb.extract_get_response_data(temp_data)

        self.assertEqual(nfb.FOUND_RESPONSE_TEXT, txt)
        self.assertEqual(self.tcp.host_info, temp_dict['tcp_addr'])
        self.assertEqual(existence_file, temp_dict['name'])

        md, src_des, temp_data = nfb.extract_udp_message(skt)
        self.assertEqual(nfb.ResponseData.command, cmd)
        txt, temp_data = nfb.extract_response_data(temp_data)
        temp_dict = nfb.extract_get_response_data(temp_data)

        self.assertEqual(nfb.FOUND_RESPONSE_TEXT, txt)
        self.assertEqual(self.tcp.host_info, temp_dict['tcp_addr'])
        self.assertEqual('Test.txt', temp_dict['name'])
        skt.close()

    def client_discovery(self):
        src = self.client
        addr = [nfb.AddressIp(IP, 4000, None, None),
                nfb.AddressIp('127.0.1.24', 2545, None, None),
                self.udp.host_info]

        dict_temp = {addr[0].ip: addr[0],
                     addr[1].ip: addr[1],
                     addr[2].ip: addr[2]}

        send, hub = nfb.is_there_next_des(src, self.udp.host_info)
        nfb.send_directory_message_to(dict_temp,
                                      src,
                                      self.udp.host_info,
                                      hub)

    def test_discovery(self):
        self.udp.start()

        sleep(.2)

        self.client_discovery()

        addr = [nfb.AddressIp(IP, 4000, None, None),
                nfb.AddressIp('127.0.1.24', 2545, None, None),
                self.client]

        dict_temp = {addr[0].ip: addr[0],
                     addr[1].ip: addr[1],
                     addr[2].ip: addr[2]}
        sleep(.2)

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

    def test_find_file(self):
        path = TEST_PATH + os.sep + 'TestUdpServer'
        dir_temp = {}
        ip = '127.0.1.17'

        temp_tcp = nfb.TcpServer(path, ip)
        temp_udp = nfb.UdpServer(path, dir_temp, threading.Lock(), ip, 40000, temp_tcp)
        temp_tcp.start()
        temp_udp.start()

        self.udp.start()
        sleep(2)
        self.udp.dis_dict.update({temp_udp.host_info.ip: temp_udp.host_info})
        state = self.udp.find_file('BACKGROUND FULL HD (5).JPG')
        self.assertIsNotNone(state)
        state = self.udp.find_file('BACKGROUND.JPG')
        self.assertIsNone(state)
        state = self.udp.find_file('BACKGROUND FULL HD (5).JPG')
        self.assertIsNotNone(state)
        temp_udp.stop()
        self.udp.stop()
        temp_tcp.stop()


class TestFilesFunction(ut.TestCase):

    def test_all(self):
        self.test_separating_and_saving_data()
        self.test_save_data()

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

    def test_save_data(self):
        path = TEST_PATH + os.sep + 'TestFilesFunction'

        file_addr = BASE_FILES_PATH + os.sep + TEST_FILE_NAME['MUSIC']
        file_test = open(file_addr, 'rb')

        file = nfb.File('test', path)

        file.save_data(bytearray(file_test.read()))
        state = check_two_file(path, 'test', BASE_FILES_PATH, TEST_FILE_NAME['MUSIC'])
        self.assertTrue(state)

        file_test.close()


class TestAllKindMessage(ut.TestCase):
    """
    test all kind of messages
    """

    def test_all(self):
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

    def test_AddressIp(self):
        ip = nfb.AddressIp(IP, 12323, None, None)
        ip2 = nfb.AddressIp(IP, 12323, None, None)
        ip3 = nfb.AddressIp('127.2.6.4', 4561, IP, None)
        ip4 = nfb.AddressIp('127.2.6.4', 4561, IP, 5523)
        self.assertEqual(ip, ip2)
        print(ip.get_file_format())
        print(ip2.get_file_format())
        print(ip3.get_file_format())
        print(ip4.get_file_format())

    def test_all(self):
        self.test_get_size_of_file()
        self.test_get_ith_mb_from()
        self.test_assemble_files()
        self.test_extract_address_ip_format()
        self.test_extract_source_and_destination()
        self.test_make_directory_dictionary()
        self.test_filter_directory_dictionary()
        self.test_prepare_directory_message()
        self.test_extract_response_data()
        self.test_prepare_response_data()
        self.test_prepare_get_response()
        self.test_extract_download_data()
        self.test_update_proxy_of_server()
        self.test_prepare_list_of_files()
        self.test_extract_list_of_files_data()
        self.test_prepare_download_message_data()
        self.test_extract_file_info()
        self.test_prepare_file_info()

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

    def test_filter_directory_dictionary(self):

        d = {self.test_address_list[1].ip: self.test_address_list[1]}
        d = nfb.filter_directory_dictionary(self.test_address_list[1],
                                            self.test_address_list[0],
                                            d)
        self.assertDictEqual({self.test_address_list[0].ip: self.test_address_list[0]},
                             d)

    def test_prepare_directory_message(self):
        test = {'amir': nfb.AddressIp('amir', 232, 'io3232', 54645, 'node_name'),
                'ali': nfb.AddressIp('ali', 545, None, None, 'node_name1')}
        test_str = '{ip}, {portNum}, {ipp}, {ppn}, {name}|{ip1}, {portNum1}, {ipp1}, {ppn1}, {name1}'.format(
            ip='amir',
            portNum=232,
            ipp='io3232',
            ppn=54645,
            ip1='ali',
            portNum1=545,
            ipp1=None,
            ppn1=None,
            name='node_name',
            name1='node_name1'
        )
        print(test['amir'])
        print(test['amir'].get_file_format())
        print(test['amir'].get_format())
        print(test_str)
        mes = nfb.prepare_directory_message(test)
        self.assertEqual(mes, test_str)

    def test_extract_response_data(self):
        test_mes = b'\x0A\x00\x00\x02h123456789\x12\x34'
        txt, raw_data = nfb.extract_response_data(bytearray(test_mes))
        self.assertEqual(txt, 'h123456789')
        self.assertEqual(raw_data, b'\x12\x34')

    def test_extract_get_response_data(self):
        temp_data = b'name:<TEST>|tcp_addr:127.0.0.5,'
        temp_data += b' 2000, 192.168.0.2, 5000,'
        temp_data += b' node0|service_mode:READY|asp:0.25'
        temp_info = nfb.extract_get_response_data(bytearray(temp_data))
        print(temp_info)
        self.assertEqual('<TEST>', temp_info['name'])
        addr = nfb.extract_address_ip_format(temp_info['tcp_addr'], is_bytes=False)[0]
        test_addr = nfb.AddressIp('127.0.0.5',
                                  2000,
                                  '192.168.0.2',
                                  5000,
                                  'node0')
        self.assertEqual(0.25, float(temp_info['asp']))
        self.assertEqual(nfb.SERVICE_MODE_READY, temp_info['service_mode'])
        self.assertEqual(test_addr, addr)

    def test_prepare_response_data(self):
        test_txt = '<TEST>'
        test_data = bytearray(b'\x12\x74')
        test_message = nfb.prepare_response_data(test_txt, test_data)

        test_data = b'\x06\x00\x00\x02<TEST>\x12\x74'

        self.assertEqual(test_message, test_data)

    def test_prepare_get_response(self):
        test_txt = '<TEST>'
        test_message = nfb.prepare_get_response(test_txt, TEST_SRC, 0.25, nfb.SERVICE_MODE_READY)

        temp1 = f'name:{test_txt}|tcp_addr:{TEST_SRC.get_format()}|service_mode:{nfb.SERVICE_MODE_READY}|'
        temp1 += f'apg:0.25'

        test_data = bytearray(temp1, nfb.ENCODE_MODE, nfb.ERROR_ENCODING)
        self.assertEqual(test_data, test_message)

    def test_extract_download_data(self):
        name = '<DOWNLOAD>'
        name_len = int.to_bytes(len(name),
                                2,
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

    def test_prepare_list_of_files(self):
        name_list = ['jack.mkv', 'hello.txt', 'music']

        test_data = bytearray('|'.join(name_list), nfb.ENCODE_MODE, nfb.ERROR_ENCODING)

        temp_data = nfb.prepare_list_of_files(name_list)
        self.assertEqual(test_data, temp_data)

    def test_extract_list_of_files_data(self):
        txt = 'name1|name2|name3|name4'
        txt_byte = txt.encode(nfb.ENCODE_MODE, nfb.ERROR_ENCODING)

        txt_list = ['name1', 'name2', 'name3', 'name4']
        self.assertListEqual(txt_list, nfb.extract_list_of_files_data(bytearray(txt_byte)))

    def test_prepare_download_message_data(self):
        name = 'Test file'
        bi_name = bytearray(b'\x00\x09') + bytearray(name, nfb.ENCODE_MODE, nfb.ERROR_ENCODING)
        self.assertEqual(bi_name, nfb.prepare_download_message_data(name))

    def test_prepare_file_info(self):
        info = nfb.prepare_file_info(name='<name>',
                                     partNums=5,
                                     not_valid_key=55,
                                     tcp_addr='127.0.2.3',
                                     apg=.25)
        print(info)
        self.assertEqual('name:<name>|partNums:5|tcp_addr:127.0.2.3|apg:0.25', info)

    def test_extract_file_info(self):
        info = 'name:<name>|partNums:5|tcp_addr:127.0.2.3|apg:0.25'
        temp_data = nfb.extract_file_info(bytearray(info.encode(nfb.ENCODE_MODE, nfb.ERROR_ENCODING)))
        temp_dict = {'name': '<name>', 'partNums': '5', 'apg': '0.25', 'tcp_addr': '127.0.2.3'}
        self.assertDictEqual(temp_dict, temp_data)


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

    def test_all(self):
        self.test_extract_udp_message()
        self.test_extract_tcp_message()

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
            temp_info = nfb.prepare_file_info(name='test', partNums=4)
            rsp_found = nfb.prepare_response_data(nfb.FOUND_RESPONSE_TEXT,
                                                  bytearray(temp_info,
                                                            nfb.ENCODE_MODE,
                                                            nfb.ERROR_ENCODING))
            s.send(nfb.ResponseData(rsp_found,
                                    nfb.AddressIp(self.server_ip,
                                                  self.server_port,
                                                  None,
                                                  None),
                                    nfb.AddressIp('127.14.0.9',
                                                  12546,
                                                  None,
                                                  None)
                                    ).get_data()
                   )
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

        nfb.extract_tcp_message(skt)

        state, name, path = nfb.recv_data(skt,
                                          TEST_PATH + os.sep + 'test_recv_data')

        skt.close()
        if state:
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
                                                   self.client,
                                                   server,
                                                   TEST_PATH + os.sep + 'test_download_file_from')
        self.assertTrue(state)
        self.assertEqual(self.file + '_part0', name)
        self.assertTrue(name in os.listdir(TEST_PATH + os.sep + 'test_download_file_from'))

        if state:
            i = name.rfind('_', 0, len(name))
            main_name = name[:i]
            nfb.assemble_files(path, name, path, main_name, start_zero=True)
