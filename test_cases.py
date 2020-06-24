import netwolf_lib as nfb
import unittest as ut
import os
import socket
from time import sleep


TEST_PATH_LIST = ['F:', 'Amir', 'University', 'Computer Network', 'Project', 'NetWolf', 'Test']
FILE_FOR_TESTING_PATH_LIST = ['F:', 'Amir', 'University', 'Computer Network', 'Project', 'NetWolf', 'Files_for_testing']
TEST_PATH = f'{os.sep}'.join(TEST_PATH_LIST)
FILE_FOR_TESTING_PATH = f'{os.sep}'.join(FILE_FOR_TESTING_PATH_LIST)
IP = socket.gethostbyname(socket.gethostname())


class TestTcpServer(ut.TestCase):

    def test_start_and_stop(self):
        tcp = nfb.TcpServer(TEST_PATH, IP, 2000)
        tcp.start()
        sleep(2)
        tcp.stop()
        sleep(1)


class TestUdpServer(ut.TestCase):

    def test_start_and_stop(self):
        udp = nfb.UdpServer(TEST_PATH, [], IP, 4433)
        udp.start()
        sleep(2)
        udp.stop()
        sleep(1)


class TestFilesFunction(ut.TestCase):

    def test_separating_and_saving_data(self):
        """
        test separate_to_mb and File.save_list_of_data
        :return:
        """
        path = TEST_PATH + os.sep + 'separating_and_saving_files'

        file1 = open(FILE_FOR_TESTING_PATH + '\\' +
                     'League Of Legends - Awaken Ft. Valerie Broussard (Official Audio) - .mp3', 'rb')

        file2 = nfb.File('test_saving_data.mp3', path)

        datafile = bytearray(file1.read())
        file2.save_list_of_data(nfb.separate_to_mb(datafile))

        file2 = open(path + os.sep + 'test_saving_data.mp3', 'rb')
        self.assertEqual(file1.seek(0, 2), file2.seek(0,2))

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
        mes = nfb.GetData(arr)
        res = mes.get_data()
        res = res[(1+len(mes.command) + 1):]
        self.assertListEqual([res], [res])

    def test_dir_message(self):
        arr = bytearray(list(range(0, 200)))
        mes = nfb.DirectoryData(arr)
        res = mes.get_data()
        res = res[(1+len(mes.command) + 1):]
        self.assertListEqual([res], [res])

    def test_res_message(self):
        arr = bytearray(list(range(0, 200)))
        mes = nfb.ResponseData(arr)
        res = mes.get_data()
        res = res[(1+len(mes.command) + 1):]
        self.assertListEqual([res], [res])


class TestFunctions(ut.TestCase):

    def test(self):
        """
        test get_size_of_file, assemble_files, get_size_of_file
        :return:
        """
        name1 = 'Awaken.mp3'
        name2 = 'download'

        des = nfb.File(name2, TEST_PATH)

        size = nfb.get_size_of_file(FILE_FOR_TESTING_PATH, name1)

        for i in range(size):
            temp_data = nfb.get_ith_mb_from(FILE_FOR_TESTING_PATH, name1, i)
            des.save_data(temp_data)

        nfb.assemble_files(TEST_PATH, 'download', TEST_PATH, 'music.mp3')

    def test_extract_directory_message(self):
        test = {'amir': (232, 'io3232', 54645), 'ali': (545, None, None)}

        test_list = " 'amir' , 232, 'io3232', 54645 | 'ali', 545, 'None', 'None'"
        temp = (test_list.encode('utf-8', 'ignore'))
        temp_res = nfb.extract_directory_message(temp)

        self.assertDictEqual(temp_res, test)

        test_list = " 'amir' , 232, 'io3232', 546,45 | 'ali', 545, 'None', 'None'"
        temp = (test_list.encode('utf-8', 'ignore'))
        temp_res = nfb.extract_directory_message(temp)

        self.assertNotEqual(temp_res, test)

    def test_prepare_directory_message(self):
        test = {'amir': (232, 'io3232', 54645), 'ali': (545, None, None)}
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
