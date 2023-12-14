## In overflow detector:
### 1) One global variable is kept and at any point it becomes non none, there is an overflow
### 2) if a libc function is called, its got entry now points to the libc address, hence, now if puts plt called with got address as parameter, it will leak the address