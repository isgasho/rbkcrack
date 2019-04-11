用法
-----

### 数据需求

发起攻击需要至少12字节的连续明文.
明文越大, 完成攻击越快.

#### 攻击zip文件

已知:
- 加密zip `encrypted.zip`, 包含文件`cipher`
- 明文zip `plain.zip`, 包含文件 `plain`

其中 `cipher` 和 `plain` 是同一个文件, 攻击命令如下:

    rbkcrack -C encrypted.zip -c cipher -P plain.zip -p plain

**[推荐]** 或者使用 `-a` 开关根据 CRC32 值自动寻找文件进行明文攻击

    rbkcrack -C encrypted.zip -P plain.zip -a
    
在目前没有 GBK 支持的情况下, 当文件名是 GBK 编码时, `-a` 开关可以省下大量时间

#### 攻击原始数据(?)

已知:
- 加密文件 `cipherfile`, 前12字节是加密头
- 已知明文(可能只是部分) `plainfile`

攻击命令如下:

    rbkcrack -c cipherfile -p plainfile

#### 偏移

如果明文对应的密文没有完全对应, 可以指定一个明文相对于密文的偏移

    rbkcrack -c cipherfile -p plainfile -o offset

### 解密

可以指定 `-d` 开关, 在攻击完成后导出解密的文件

    rbkcrack -c cipherfile -p plainfile -d decipheredfile

如果 keys 已知(在上一次攻击中得到), 可以直接导出解密后的文件

    rbkcrack -c cipherfile -k 12345678 23456789 34567890 -d decipheredfile

### 解压

解密后的文件可能仍然处于压缩状态, 如果使用了 deflate 压缩算法(一般都是), 可以使用 `tools` 文件夹里的 Python3 脚本来解压

    tools/inflate.py < decipheredfile > decompressedfile

也可以直接指定 `-u` 开关来让 rbkcrack 自动解压

    rbkcrack -C encrypted.zip -c cipher -P plain.zip -p plain -d final -u
    
**[推荐]** 如果想解压整个文件的话, 可以使用这个改造过的可以用 keys 解压的 [p7zip](https://github.com/Aloxaf/p7zip):

    7za e cipher.zip '-p[d4f34b9d_a6ba3461_dcd97451]'

贡献    
---

欢迎 PR

顺便, 如果有啥 rbkcrack 破解不了的 zip 文件的话, 欢迎提 issue
