# TCPPacketCollector_Libpcap

## Installation

* You should install libpcap first.
* Gcc also

For old version:(not recommended.)

```
make main
```

For new version:

```
make main2
```

The only difference between them is the method of storing the data in the memory.

* By the way

  If you want to disable the output to increase the performace, you should change the main.c and remove `#define DEBUG`

## How to use

```bash
./build/main Interface IP dest
```

* Example

  ```bash
  ./build/main eth0 192.168.1.3 ./data.bin
  ```

`dest` will be a binary file, that you can read the data use the struct in `mdata.h` called `struct mdata`

It stored the (src_ip, dst_ip, src_port, dst_port, protocol, delay)

* You can see the libpcap's speed with the prefix [LIBPCAP]

* You can see the server's reaction speed with the prefix [WITH XXX]

* You can see the peak memory with the prefix [MEMORY]

* You should change the 2200000 to you CPU cycles per sec in main.c before compile.

