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


def ser():
    addr = socket.gethostbyname(socket.gethostname())
    port = 20005

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


# %%
def cli():
    addr = socket.gethostbyname(socket.gethostname())
    port = 20005

    host_information = (addr, port)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    meg = "hello server".encode()
    print('send')
    client.sendto(meg, host_information)


import threading
from time import sleep

t1 = threading.Thread(target=ser)
t2 = threading.Thread(target=cli)

t1.start()
t2.start()

