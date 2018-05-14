#!/usr/bin/python
'''
crackme have tow level check
level2 is diffcult than level1 so we use thi specil way to skip it
just find right key for level1 and run program to check
if you want run faster,you can change main() to alway goto main()
'''
from pwn import *
context.log_level = 'error'
pa = [0x23, 0x19, 0x16, 0x22, 0x8, 0x17, 0x18, 0x12, 0x17, 0x1C, 0x1, 0x21]
pb = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ~!@#$%^&*_-"
pb = list(pb)
buff = ""
def find(x,last):
  global buff
  if x==12:
    test(buff)
    return
  for a in pb:
    if (ord(a)+last)%0x25==pa[x]:
      buff = buff + a
      find(x+1,ord(a)+last)
      buff=buff[:-1]
def test(pwd):
  p = process("./crackme")
  p.sendline(pwd)
  try:
    p.recvuntil('Well done')
  except:
    p.close()
    return False
  p.close()
  print pwd
  print "Success!"
  exit()
  return True
#start
find(0,0)

