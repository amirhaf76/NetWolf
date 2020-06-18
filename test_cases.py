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


class TestFilesFunction(ut.TestCase):

    def test_separating_and_saving_data(self):
        """
        test separate_to_mb and File.save_list_of_data
        :return:
        """
        file1 = open(FILE_FOR_TESTING_PATH + '\\' +
                     'League Of Legends - Awaken Ft. Valerie Broussard (Official Audio) - .mp3', 'rb')

        file2 = nfb.File('test_saving_data.mp3', TEST_PATH)

        datafile = bytearray(file1.read())
        file2.save_list_of_data(nfb.separate_to_mb(datafile))
        file1.close()
