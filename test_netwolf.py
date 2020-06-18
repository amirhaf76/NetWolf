import netwolf_lib as nfb
import os
import threading

test_path_list = ['F:', 'AmirUniversity', 'Computer Network', 'Project', 'NetWolf', 'test']
test_path = f'{os.sep}'.join(test_path_list)

tcp = nfb.TcpServer(test_path, '192.168.1.6', 2000)
tcp.start()
