# sn://wg WireGuard URI 编解码工具

将标准 WireGuard 配置文件编码为紧凑的 sn://wg? URI，或反向解码。

---

## 快速开始

```bash
# 编码
py 1.py e wg.conf
py 1.py e wg.conf -o uri.txt
py 1.py e a.conf b.conf c.conf

# 解码
py 1.py d "sn://wg?eNpj..."
py 1.py d nodes.txt
py 1.py d "sn://..." -o wg.conf

# 日志
py 1.py e wg.conf -v
py 1.py d uri.txt -o out.conf -v
```

---

## 编码原理

整体流程：
wg.conf文本 -> 解析提取 -> 二进制序列化 -> zlib压缩 -> Base64URL编码 -> 拼接前缀

1. 解析 wg.conf
从标准配置中提取关键字段，舍弃冗余信息：
- [Interface] 提取 Address, PrivateKey, MTU
- [Peer] 提取 PublicKey, PresharedKey, Endpoint (拆分为IP和端口), PersistentKeepalive

2. 二进制序列化
将字典按固定顺序写入字节流，无分隔符、无字段名，纯靠位置区分。
结构：版本(4B) + IP文本 + 端口(4B) + 地址文本 + 私钥文本 + 公钥文本 + 预共享密钥文本 + MTU(2B) + 保留(2B) + [Keepalive标记(1B) + Keepalive值(4B)]

3. 文本字段的无长度前缀编码 (核心设计)
常规做法是为每个字符串存长度前缀(如uint16)，但对于大量短字符串，每个前缀浪费2字节。
本格式采用末字节标记法：
- 将字符串除最后一个字符外的部分，原样转为 UTF-8 字节
- 将最后一个字符的 ASCII 码与 0x80 进行按位或 (|) 操作，作为终止符附加在末尾
- 示例："1.2.3.4" -> 31 2E 32 2E 33 2E B4 (末尾的 4 变成了 0x80|0x34)
- 解码时，顺序读取字节，遇到 >= 0x80 的字节即判定字符串结束，并将其与 0x7F 按位与 (&) 还原出最后一个字符
- 此法既省去了所有长度前缀，又能完美兼容任意长度的字符串

4. zlib 极限压缩
使用 zlib.compress(level=9) 对二进制流进行极限压缩。
由于大量重复的 Base64 密钥字符以及固定的结构性字节，压缩率极高，通常能将 200+ 字节的原始数据压缩至 100 字节左右。

5. Base64URL 安全编码
将压缩后的二进制数据使用标准 Base64 编码，并做 URL 安全替换：
- + 替换为 -
- / 替换为 _
- 移除末尾的 = 填充符
最终拼接 "sn://wg?" 前缀，形成可直接在网页、二维码中使用的合法 URI。

---

## 免责声明

本工具及配套说明文档完全由人工智能模型 GLM-5 生成，代码经过人工审查。