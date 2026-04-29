#!/usr/bin/env python3
"""
sn://wg WireGuard URI 编解码工具

用法:
  py 1.py                          显示帮助
  py 1.py -h / --help
  py 1.py e wg.conf                编码 wg.conf → URI
  py 1.py e a.conf b.conf          批量编码
  py 1.py e wg.conf -o uri.txt     编码并保存
  py 1.py d "sn://wg?eNpj..."      解码 URI 字符串
  py 1.py d uri.txt                读取文件, 批量解码其中的 sn:// URI
  py 1.py d "sn://..." -o wg.conf  解码并保存为 conf
"""

import base64, zlib, struct, os, sys, re, argparse


# ================================================================
#  Base64URL
# ================================================================
def b64url_encode(data: bytes) -> str:
    return (base64.b64encode(data).decode("ascii")
            .rstrip("=").replace("+", "-").replace("/", "_"))


def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.b64decode(s)


# ================================================================
#  文本字段编解码
# ================================================================
def _encode_text(text: str) -> bytes:
    """末字符用 0x80|ord(char) 编码"""
    if not text:
        return b""
    return text[:-1].encode("utf-8") + bytes([0x80 | ord(text[-1])])


def _decode_text(data: bytes, pos: int):
    """读到 >= 0x80 的字节, & 0x7F 还原末字符"""
    start = pos
    while pos < len(data) and data[pos] < 0x80:
        pos += 1
    if pos < len(data):
        lc = chr(data[pos] & 0x7F)
        pos += 1
        return data[start:pos - 1].decode("utf-8") + lc, pos
    return data[start:].decode("utf-8"), pos


# ================================================================
#  二进制编解码
# ================================================================
def encode_binary(cfg: dict) -> bytes:
    buf = bytearray()
    buf += struct.pack("<I", cfg.get("version", 2))
    buf += _encode_text(cfg["endpoint_ip"])
    buf += struct.pack("<I", cfg["endpoint_port"])
    buf += _encode_text(cfg["interface_address"])
    buf += _encode_text(cfg["private_key"])
    buf += _encode_text(cfg["public_key"])
    buf += _encode_text(cfg["preshared_key"])
    buf += struct.pack("<HH", cfg.get("mtu", 1420), 0)
    ka = cfg.get("keepalive", 0)
    if ka > 0:
        buf += b"\x81"
        buf += struct.pack("<I", ka)
    extra = cfg.get("extra_flags", "")
    if extra:
        buf += bytes.fromhex(extra)
    return bytes(buf)


def decode_binary(data: bytes) -> dict:
    pos = 0
    cfg = {}
    cfg["version"] = struct.unpack_from("<I", data, pos)[0]; pos += 4
    cfg["endpoint_ip"], pos = _decode_text(data, pos)
    cfg["endpoint_port"] = struct.unpack_from("<I", data, pos)[0]; pos += 4
    cfg["interface_address"], pos = _decode_text(data, pos)
    cfg["private_key"], pos = _decode_text(data, pos)
    cfg["public_key"], pos = _decode_text(data, pos)
    cfg["preshared_key"], pos = _decode_text(data, pos)
    cfg["mtu"] = struct.unpack_from("<H", data, pos)[0]; pos += 4
    if pos < len(data) and data[pos] == 0x81:
        pos += 1
        cfg["keepalive"] = struct.unpack_from("<I", data, pos)[0]; pos += 4
    else:
        cfg["keepalive"] = 0
    cfg["extra_flags"] = data[pos:].hex() if pos < len(data) else ""
    return cfg


# ================================================================
#  wg.conf 解析 / 生成
# ================================================================
def parse_wg_conf(text: str) -> dict:
    cfg = {
        "interface_address": "", "private_key": "", "mtu": 1420,
        "public_key": "", "preshared_key": "", "endpoint_ip": "",
        "endpoint_port": 51820, "keepalive": 0, "extra_flags": "818181",
    }
    section = None
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line.lower(); continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip().lower(), val.strip()
        if section == "[interface]":
            if key == "address":        cfg["interface_address"] = val
            elif key == "privatekey":   cfg["private_key"] = val
            elif key == "mtu":          cfg["mtu"] = int(val)
        elif section == "[peer]":
            if key == "publickey":      cfg["public_key"] = val
            elif key == "presharedkey": cfg["preshared_key"] = val
            elif key == "endpoint":
                if "]" in val:
                    a, _, p = val.rpartition(":")
                    cfg["endpoint_ip"] = a.strip("[] ")
                    cfg["endpoint_port"] = int(p)
                else:
                    a, _, p = val.rpartition(":")
                    cfg["endpoint_ip"] = a.strip()
                    cfg["endpoint_port"] = int(p)
            elif key == "persistentkeepalive":
                cfg["keepalive"] = int(val)
    return cfg


def build_wg_conf(cfg: dict) -> str:
    lines = [
        "[Interface]",
        f"Address = {cfg['interface_address']}",
        f"PrivateKey = {cfg['private_key']}",
        f"MTU = {cfg['mtu']}",
        "",
        "[Peer]",
        f"PublicKey = {cfg['public_key']}",
        f"PresharedKey = {cfg['preshared_key']}",
        f"Endpoint = {cfg['endpoint_ip']}:{cfg['endpoint_port']}",
        "AllowedIPs = 0.0.0.0/0",
    ]
    if cfg.get("keepalive", 0) > 0:
        lines.append(f"PersistentKeepalive = {cfg['keepalive']}")
    return "\n".join(lines)


# ================================================================
#  高层: 编码 / 解码
# ================================================================
def do_encode(conf_text: str, verbose: bool = False) -> str:
    cfg = parse_wg_conf(conf_text)
    if verbose:
        print("  [parse] Endpoint   "
              f"{cfg['endpoint_ip']}:{cfg['endpoint_port']}")
        print(f"  [parse] Address    {cfg['interface_address']}")
        print(f"  [parse] MTU        {cfg['mtu']}")
        print(f"  [parse] Keepalive  {cfg['keepalive']}")
        print(f"  [parse] PrivKey    {cfg['private_key'][:20]}...")
        print(f"  [parse] PubKey     {cfg['public_key'][:20]}...")
    raw = encode_binary(cfg)
    if verbose:
        print(f"  [bin]   {len(raw)} bytes")
    compressed = zlib.compress(raw, 9)
    if verbose:
        print(f"  [zlib]  {len(compressed)} bytes (level 9)")
    uri = f"sn://wg?{b64url_encode(compressed)}"
    if verbose:
        print(f"  [b64]   {len(uri)} chars")
    return uri


def do_decode(uri: str, verbose: bool = False) -> str:
    if verbose:
        print(f"  [input] {uri[:72]}{'...' if len(uri) > 72 else ''}")
    payload = uri.split("?", 1)[1] if "?" in uri else uri
    raw = b64url_decode(payload)
    if verbose:
        print(f"  [b64]   decoded {len(raw)} bytes")
    data = zlib.decompress(raw)
    if verbose:
        print(f"  [zlib]  decompressed {len(data)} bytes")
        print(f"  [bin]   {data.hex()}")
    cfg = decode_binary(data)
    if verbose:
        for k, v in cfg.items():
            print(f"  [field] {k:20s} = {v}")
    return build_wg_conf(cfg)


# ================================================================
#  辅助
# ================================================================
def is_sn_uri(s: str) -> bool:
    return s.strip().startswith("sn://wg")


def extract_uris(text: str) -> list:
    """从文件内容提取所有 sn://wg? URI"""
    uris = []
    for line in text.splitlines():
        line = line.strip()
        if is_sn_uri(line):
            uris.append(line)
        else:
            found = re.findall(r'sn://wg\?[A-Za-z0-9_\-]+', line)
            uris.extend(found)
    return uris


# ================================================================
#  CLI
# ================================================================
def build_parser():
    p = argparse.ArgumentParser(
        prog="py 1.py",
        description="sn://wg WireGuard URI 编解码工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  py 1.py                          显示帮助
  py 1.py e wg.conf                编码 wg.conf → 输出 URI
  py 1.py e a.conf b.conf          批量编码多个 conf
  py 1.py e wg.conf -o uri.txt     编码并保存到文件
  py 1.py e wg.conf -v             编码 (详细日志)
  py 1.py d "sn://wg?eNpj..."      解码 URI 字符串
  py 1.py d nodes.txt              从文件批量解码 sn:// URI
  py 1.py d "sn://..." -o wg.conf  解码并保存为 conf 文件
  py 1.py de uri.txt -o wg.conf -v 解码 (详细日志 + 保存)
""",
        add_help=False,
    )
    p.add_argument("-h", "--help", action="store_true",
                  help="显示帮助信息")
    p.add_argument("-v", "--verbose", action="store_true",
                  help="详细日志")
    p.add_argument("-o", "--output", default=None,
                  help="保存到指定文件")
    p.add_argument("action", nargs="?", default=None,
                  help="e/en/encode 或 d/de/decode")
    p.add_argument("targets", nargs="*",
                  help="文件路径 或 sn:// URI 字符串")
    return p


def main():
    parser = build_parser()

    # 无参数 → 显示帮助
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # -h → 显示帮助
    if args.help:
        parser.print_help()
        sys.exit(0)

    # 必须有 action
    if not args.action:
        print("错误: 未指定操作, 请使用 e/encode 或 d/decode\n")
        parser.print_help()
        sys.exit(1)

    act = args.action.lower()
    verbose = args.verbose
    output = args.output

    # ===================== 编码模式 =====================
    if act in ("e", "en", "encode"):
        if not args.targets:
            print("错误: 请指定要编码的 wg.conf 文件\n")
            print("用法: py 1.py e wg.conf [wg2.conf ...] [-o output]")
            sys.exit(1)

        results = []
        for fpath in args.targets:
            if not os.path.isfile(fpath):
                print(f"跳过 (不存在): {fpath}")
                continue
            with open(fpath, "r", encoding="utf-8") as f:
                text = f.read()
            if verbose:
                print(f"[*] 编码: {fpath}")
            uri = do_encode(text, verbose)
            results.append((fpath, uri))
            if verbose:
                print(f"    URI: {uri[:72]}...\n")
            else:
                print(uri)

        # 保存
        if output and results:
            with open(output, "w", encoding="utf-8") as f:
                for fp, uri in results:
                    f.write(uri + "\n")
            print(f"\n已保存 {len(results)} 条 URI → {output}")

    # ===================== 解码模式 =====================
    elif act in ("d", "de", "decode"):
        if not args.targets:
            print("错误: 请指定要解码的 URI 或文件\n")
            print("用法: py 1.py d <URI或文件> [-o output]")
            sys.exit(1)

        results = []
        for target in args.targets:
            # 判断: URI 字符串 还是 文件路径
            if is_sn_uri(target):
                # 直接解码 URI
                if verbose:
                    print(f"[*] 解码 URI: {target[:72]}...")
                conf = do_decode(target, verbose)
                results.append(("URI", conf))
                if not output:
                    print(conf + "\n")
                elif verbose:
                    print()
            elif os.path.isfile(target):
                # 读文件, 提取 sn:// URI
                with open(target, "r", encoding="utf-8") as f:
                    content = f.read()
                uris = extract_uris(content)
                if not uris:
                    print(f"文件 {target} 中未找到 sn:// URI")
                    continue
                if verbose:
                    print(f"[*] 文件: {target}  ({len(uris)} 个 URI)\n")
                for i, uri in enumerate(uris, 1):
                    if verbose:
                        print(f"  --- [{i}/{len(uris)}] ---")
                    conf = do_decode(uri, verbose)
                    results.append((f"{target}[{i}]", conf))
                    if not output:
                        print(conf)
                        if i < len(uris):
                            print()
                    elif verbose:
                        print()
            else:
                print(f"跳过 (不存在): {target}")

        # 保存
        if output and results:
            with open(output, "w", encoding="utf-8") as f:
                for src, conf in results:
                    f.write(conf + "\n\n")
            print(f"\n已保存 {len(results)} 条配置 → {output}")

    else:
        print(f"错误: 未知操作 '{args.action}', 请使用 e/encode 或 d/decode\n")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
