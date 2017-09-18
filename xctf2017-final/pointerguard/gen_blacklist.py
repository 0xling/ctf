__author__ = "pxx"

def read_file(file_name, mode = "r"):
	file_r = open(file_name, mode)
	data = file_r.read()
	file_r.close()
	return data

def wirte_file(file_name, data, mode = "w"):
	file_w = open(file_name, mode)
	file_w.write(data)
	file_w.close()

bin_list = []
libc_list = []
stack_list = []

def add_to_list(list_t, info, offset_max, base = 0):
	for line in info.split('\n'):
		line_item = line.split(' = ')
		if len(line_item) == 2:
			addr = int(line_item[1], 16)
			addr -= base
			for i in range(offset_max):
				#print len(list_t)
				list_t.append(addr - i)

bin_info = """  
free_got                   = 0x0000000000602018  
strncmp_got                = 0x0000000000602020  
puts_got                   = 0x0000000000602028  
strlen_got                 = 0x0000000000602030  
__stack_chk_fail_got       = 0x0000000000602038  
printf_got                 = 0x0000000000602050  
strcmp_got                 = 0x0000000000602070  
getchar_got                = 0x0000000000602078  
malloc_got                 = 0x0000000000602088  
realloc_got                = 0x0000000000602090  
atol_got                   = 0x0000000000602098   
exit_got                   = 0x00000000006020b0
"""
offset_max = 8 - 3 + 1
#bin
binary_base = 0x400000
add_to_list(bin_list, bin_info, offset_max, binary_base)
bin_list.append(0)

#libc
libc_info = """
malloc_hook = 0x3C4B10
realloc_hook = 0x3C4B08
free_hook = 0x3C67A8
stdout_addr = 0x3C56f8
stdin_addr = 0x3c49b8
stderr_addr = 0x3c5618
morecore_hook                 = 0x3C53B0
after_morecore_hook                 = 0x3C67A0
dtor_addr                 = 0x5cf700
unsort_bin_addr = 0x3c4bc8
"""

stdout_addr = 0x3C5620
stdin_addr = 0x3C48E0
stderr_addr = 0x3C5540

print hex(stdout_addr + 0xd8)
print hex(stdin_addr + 0xd8)
print hex(stderr_addr + 0xd8)

add_to_list(libc_list, libc_info, offset_max)
libc_list.append(0)

#libc_list.append(malloc_hook)
#libc_list.append(realloc_hook)

#stack
#stack_list.append(0x14) #set_val stack
#stack_list.append(0xd4) #main stack
stack_info = """
addr = 0x14
addr = 0xd4
"""
add_to_list(stack_list, stack_info, offset_max)
stack_list.append(0)

def ljust_list(list_t, size, val):
	return list_t + [val]*(size - len(list_t))

bin_list = ljust_list(bin_list, 100, bin_list[-1])
libc_list = ljust_list(libc_list, 100, libc_list[-1])
stack_list = ljust_list(stack_list, 100, stack_list[-1])

print len(bin_list)
print len(libc_list)
print len(stack_list)

list_all = bin_list + libc_list + stack_list
all_content = "".join("0x%x\n"%addr for addr in list_all)
wirte_file("./blacklist", all_content)