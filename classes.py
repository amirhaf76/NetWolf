class NetWolf:
    """
    This is main class of NetWolf project
    date: 6/8/2020
    author: Amirhosein Amir Firouzkouhi ( 9528007)
    """

    def start(self):
        pass

    def stop(self):
        pass

    def __start_user_command(self):
        pass

    def __str__(self):
        return "Net wolf < version 1>"


import socket

from time import sleep
def ser(port:int):
    addr = socket.gethostbyname(socket.gethostname())
    host_information = (addr, port)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.bind(host_information)

    while True:
        print('server is on')
        data, ad = s.recvfrom(1024)
        print('message{}'.format(data))
        print('addr{}'.format(ad))
        if data == 'exit':
            break



def server_tcp():
    addr = socket.gethostbyname(socket.gethostname())

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((addr, 2005))
    host_info = (addr, s.getsockname()[1])
    s.listen(5)
    while True:
        print('server is on')
        c, ad = s.accept()
        data = c.recv(1024)
        meg = data.decode('utf-8', 'ignore')
        print(meg[-4:])
        print(str(meg[-4:]) == 'exit')
        if str(meg[-4:]) == 'exit':
            break
    s.close()

def cli_tcp(port, meg):
    addr = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(addr, port)
    s.connect((addr, port))
    l = bytearray(meg, 'utf-8', "ignore")

    data = b'0'*(1024-len(l)) + l
    s.send(data)
    s.close()


def cli():
    addr = socket.gethostbyname(socket.gethostname())
    port = 20005

    host_information = (addr, port)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    meg = "hello server".encode()
    print('send')
    client.sendto(meg, host_information)

def hello(a):
    sleep(.5)
    print(a[0])

import threading
from concurrent.futures import ThreadPoolExecutor



t1 = threading.Thread(target=server_tcp)

t2 = threading.Thread(target=cli_tcp, args=(2005, "hi"))
t3 = threading.Thread(target=cli_tcp, args=(2005, "her"))
t4 = threading.Thread(target=cli_tcp, args=(2005, "exit"))
# t3 = ThreadPoolExecutor(max_workers=5)


t1.start()
sleep(2)
t2.start()
sleep(2)
t3.start()
sleep(2)
t4.start()


