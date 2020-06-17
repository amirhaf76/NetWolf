import netwolf_lib as nfb
import unittest as ut
import os


test_path_list = ['F:', 'AmirUniversity', 'Computer Network', 'Project', 'NetWolf', 'test']
test_path = f'{os.sep}'.join(test_path_list)

tcp = nfb.TcpServer(test_path)
tcp.start()
