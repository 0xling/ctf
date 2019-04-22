from zio import *
with open('./image2.bin', 'rb') as f:
    d = f.read()

d = d[0xd48+0x200:]

index = 0
while True:
    op = l32(d[index:index+4])
    i = l32(d[index+4:index+8])
    j = l32(d[index+8:index+0xc])
    print '%x:'%(index/4),
    if op == 0x21:#0xb7c
        print 'mov reg%d, %x' %(i, j)
    elif op == 0x22:#0xb8a
        print 'mov reg%d, reg%d' %(i, j)
    elif op == 0x23:#0xba1
        print 'mov reg%d, [reg%d]' %(i, j)
    elif op == 0x24:#0xbc1
        print 'mov [reg%d], reg%d' %(i, j)
    elif op == 0x25:#0xbe1
        print 'add reg%d, reg%d' %(i, j)
    elif op == 0x26:#0xbfc
        print 'sub reg%d, reg%d' %(i, j)
    elif op == 0x27:#0xc17
        print 'xor reg%d, reg%d' %(i, j)
    elif op == 0x28:#0xc32
        print 'shl reg%d, reg%d' %(i, j)
    elif op == 0x2d:#0xcb5
        print 'jz reg%d, reg%d' %(i, j)
    elif op == 0x2f:#0xce0
        print 'correct'
    elif op == 0x30:#0xcd4
        print 'wrong'
    else:
        print 'not known op', hex(op)
        break
    index += 12

'''
ds = [0x5f3e5a38 ,0x0d5a0b5d,0x481d4948,0x0f5d0d15,0x0555495d,	0x5e120e54,	0x12065209,	0x575e035e,0x0f590000]
data = ''
for d in ds:
    data += l32(d)

with open('./image2.bin', 'rb') as f:
    d = f.read()

d3 = d[0:0x1170]+data+d[0x1170+len(data):]

with open('./image3.bin', 'wb') as f:
    f.write(d3)
'''

'''
a = '8bdae456-5ac8-11e9-a1c1-88e9fe80feaf'
t = 0
for i in range(9):
    d = l32(a[4*i:i*4+4])
    d = d<<8^d
    d = d<<8^d
    d = d<<8^d
    d = (d&0xffffffff)
    t2 = t
    t = d
    d = d ^ t2
    print hex(d)
'''
with open('./image.bin', 'rb') as f:
    ori = f.read()

ds = ori[0x1170:0x1170+9*4]

t = 0
flag = ''
for i in range(9):
    d = l32(ds[i*4:i*4+4])
    t2 = t
    d = d ^ t2
    t = d
    d = d<<8^d
    d = (d&0xffffffff)
    print hex(d), l32(d)
    flag += l32(d)

print flag

patch = ori[0:0x114c]+flag+ori[0x1170:]
with open('./image.bin.patch', 'wb') as f:
    f.write(patch)

