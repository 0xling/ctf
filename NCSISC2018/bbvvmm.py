from zio import *
with open('./bbvvmm', 'rb') as f:
    d = f.read()

code = d[0x90e0:0x90e0+220]

#print code.encode('hex')
index = 0
while index < 220:
    opcode = ord(code[index])
    if opcode == 176:
        v = l32(code[index+1:index+5])
        print '%x: push %x' %(index, v)
        index += 5
    elif opcode == 181:
        v = l8(code[index+1:index+2])
        print '%x: pop reg%d' %(index, v)
        index += 2
    elif opcode == 178:
        v = l8(code[index+1:index+2])
        print '%x: push reg%d' %(index, v)
        index += 2
    elif opcode == 180:
        v = l8(code[index+1:index+2])
        print '%x: pop mem%d' %(index, v)
        index += 2
    elif opcode == 4:
        v = l8(code[index+1:index+2])
        v2 = l8(code[index+2:index+3])
        print '%x: mov mem%d, reg%d' %(index, v2, v)
        index += 3
    elif opcode == 144:
        v = l32(code[index+1:index+5])
        print '%x: jmp %x' %(index, v)
        index += 5
    elif opcode == 145:
        print '%x: nop' %index
        index += 1
    elif opcode == 1:
        v = l8(code[index+5:index+6])
        v2 = l32(code[index+1:index+5])
        print '%x: mov reg%d, %x' %(index, v, v2)
        index += 6
    elif opcode == 2:
        v = l8(code[index+1:index+2])
        v2 = l8(code[index+2:index+3])
        print '%x: mov reg%d, mem%d' %(index, v2, v)
        index += 3
    elif opcode == 16:
        v = l8(code[index+1:index+2])
        v2 = l32(code[index+2:index+6])
        v3 = l8(code[index+6:index+7])
        print '%x: add reg%d, reg%d, %x' %(index, v3, v, v2)
        index += 7
    elif opcode == 192:
        print '%x: add' %index
        index += 1
    elif opcode == 177:
        v = l8(code[index+1:index+2])
        print '%x: push mem%d' %(index, v)
        index += 2
    elif opcode == 112:
        v = l8(code[index+1:index+2])
        v2 = l32(code[index+2:index+6])
        v3 = l8(code[index+6:index+7])
        print '%x: xor reg%d, reg%d, %x' %(index, v3, v, v2)
        index += 7
    elif opcode == 80:
        v = l8(code[index+1:index+2])
        v2 = l32(code[index+2:index+6])
        v3 = l8(code[index+6:index+7])
        print '%x: shl reg%d, reg%d, %x' %(index, v3, v, v2)
        index += 7
    elif opcode == 200:
        print '%x: shr' %index
        index += 1
    elif opcode == 195:
        print '%x: xor' %index
        index += 1
    elif opcode == 17:
        v = l8(code[index+1:index+2])
        v2 = l8(code[index+2:index+3])
        v3 = l8(code[index+3:index+4])
        print '%x: add reg%d, reg%d, reg%d' %(index, v3, v, v2)
        index += 4
    elif opcode == 134:
        v = l8(code[index+1:index+2])
        v2 = l32(code[index+2:index+6])
        v3 = l8(code[index+6:index+7])
        print '%x: cmp reg%d, reg%d, %x' %(index, v3, v, v2)
        index += 7
    elif opcode == 136:
        v = l8(code[index+1:index+2])
        v2 = l32(code[index+2:index+6])
        print '%x: jcc %x, reg%d' %(index, v2, v)
        index += 6
    elif opcode == 255:
        break
    else:
        print 'not known:', opcode, index
        break

