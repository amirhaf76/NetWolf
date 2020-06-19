import netwolf_lib as nfb
import unittest as ut
import os
import socket
from time import sleep
from math import ceil

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
        name1 = 'Awaken.mp3'
        name2 = 'download'

        des = nfb.File(name2, TEST_PATH)

        size = nfb.get_size_of_file(FILE_FOR_TESTING_PATH, name1)

        for i in range(size):
            temp_data = nfb.get_ith_mb_from(FILE_FOR_TESTING_PATH, name1, i)
            des.save_data(temp_data)

        nfb.assemble_files(TEST_PATH, 'download', TEST_PATH, 'music.mp3')


