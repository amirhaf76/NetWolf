import netwolf_lib as nfb
import unittest as ut
import os
import socket
from time import sleep
from math import ceil


LIST_TEST_PATH = ['F:', 'Amir', 'University', 'Computer Network', 'Project', 'NetWolf', 'Test']
LIST_BASE_FILES_PATH = ['F:', 'Amir', 'University', 'Computer Network', 'Project', 'NetWolf', 'Files_for_testing']
TEST_PATH = f'{os.sep}'.join(LIST_TEST_PATH)
BASE_FILES_PATH = f'{os.sep}'.join(LIST_BASE_FILES_PATH)
IP = socket.gethostbyname(socket.gethostname())

TEST_FILE_NAME = {'MUSIC': 'Awaken.mp3', 'PICTURE': 'BACKGROUND FULL HD (5).JPG'}


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

    def test_get_size_of_file(self):
        size = ceil(7902383/(10**6))
        file_size = nfb.get_byte_size_of_file(BASE_FILES_PATH, 'Awaken.mp3')
        self.assertEqual(size, file_size, msg='Error in test_get_size_of_file')

    def test_get_ith_mb_from(self):
        name = 'download'
        path = TEST_PATH+os.sep+self.test_get_ith_mb_from.__name__

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

    def test_extract_directory_message(self):
        test = {'amir': (232, 'io3232', 54645), 'ali': (545, None, None)}

        test_list = " 'amir' , 232, 'io3232', 54645 | 'ali', 545, 'None', 'None'"
        temp = (test_list.encode('utf-8', 'ignore'))
        temp_res = nfb.make_directory_dictionary(temp)

        self.assertDictEqual(temp_res, test)

        test_list = " 'amir' , 232, 'io3232', 546,45 | 'ali', 545, 'None', 'None'"
        temp = (test_list.encode('utf-8', 'ignore'))

        try:
            temp_res = nfb.make_directory_dictionary(temp)
            self.assertNotEqual(temp_res, test)
        except nfb.NotMatchFormat:
            pass

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
