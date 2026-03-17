#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyWxDump Bridge Script for WeFlow

用法:
  python pywxdump_bridge.py get_key
  python pywxdump_bridge.py decrypt <key> <db_path> <out_path>
  python pywxdump_bridge.py decrypt_dir <key_or_json> <db_dir> <out_dir>

输出: JSON 格式到 stdout
"""
import sys
import os
import json
import shutil

# ---------------------------------------------------------------------------
# 路径解析：脚本位于 WeFlow/resources/，PyWxDump 在工作区根目录同级
# 工作区结构:
#   <workspace>/
#     PyWxDump/
#     WeFlow/
#       resources/
#         pywxdump_bridge.py   <-- 本文件
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_WEFLOW_DIR = os.path.dirname(_SCRIPT_DIR)
_WORKSPACE_ROOT = os.path.dirname(_WEFLOW_DIR)
_PYWXDUMP_PATH = os.path.join(_WORKSPACE_ROOT, 'PyWxDump')

# 支持环境变量覆盖
_ENV_PATH = os.environ.get('PYWXDUMP_PATH', '')
for _p in [_ENV_PATH, _PYWXDUMP_PATH]:
    if _p and os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)


def _out(data: dict):
    print(json.dumps(data, ensure_ascii=False))
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# cmd: get_key
# 从运行中的微信进程内存获取数据库密钥
# ---------------------------------------------------------------------------
def cmd_get_key():
    try:
        from pywxdump import WX_OFFS
        from pywxdump.wx_core.wx_info import get_wx_info
        result = get_wx_info(WX_OFFS)
        if not result:
            _out({"success": False, "error": "未找到微信进程或密钥，请确保微信已登录并运行"})
            return

        accounts = []
        for info in result:
            accounts.append({
                "pid":       info.get("pid"),
                "version":   info.get("version"),
                "wxid":      info.get("wxid"),
                "account":   info.get("account"),
                "nickname":  info.get("nickname"),
                "key":       info.get("key"),       # 64位hex，旧版 WeChat 3.x
                "wx_dir":    info.get("wx_dir"),
                # 新版 Weixin 4.x 每个 DB 独立密钥: {salt_hex: key_hex}
                "wcdb_keys": info.get("wcdb_keys"),
            })
        _out({"success": True, "accounts": accounts})

    except ImportError as e:
        _out({"success": False,
              "error": f"PyWxDump 未找到，请确认路径: {_PYWXDUMP_PATH}\n详情: {e}"})
    except Exception as e:
        _out({"success": False, "error": str(e)})


# ---------------------------------------------------------------------------
# cmd: decrypt  <key> <db_path> <out_path>
# 解密单个数据库文件
# ---------------------------------------------------------------------------
def cmd_decrypt(key: str, db_path: str, out_path: str):
    try:
        from pywxdump.wx_core.decryption import decrypt
        ok, result = decrypt(key, db_path, out_path)
        if ok:
            _out({"success": True, "in": result[0], "out": result[1], "key": result[2]})
        else:
            _out({"success": False, "error": str(result)})
    except ImportError as e:
        _out({"success": False, "error": f"PyWxDump 未找到: {e}"})
    except Exception as e:
        _out({"success": False, "error": str(e)})


# ---------------------------------------------------------------------------
# cmd: decrypt_dir  <key_or_json> <db_dir> <out_dir>
# 批量解密目录下所有 .db 文件
#   key_or_json: 64位hex（旧版单密钥）或 JSON {salt_hex: key_hex}（新版多密钥）
# ---------------------------------------------------------------------------
def cmd_decrypt_dir(key_or_json: str, db_dir: str, out_dir: str):
    try:
        from pywxdump.wx_core.decryption import decrypt

        os.makedirs(out_dir, exist_ok=True)

        # 解析密钥参数
        salt_to_key = None
        single_key = None
        stripped = key_or_json.strip()
        if stripped.startswith('{'):
            try:
                salt_to_key = json.loads(stripped)
            except Exception:
                _out({"success": False, "error": "key_or_json JSON 解析失败"})
                return
        else:
            single_key = stripped

        results = []
        errors = []

        for root, dirs, files in os.walk(db_dir):
            # 排除已是解密输出目录的子目录（以 de_ 开头的文件已处理）
            for fname in sorted(files):
                if not fname.endswith('.db'):
                    continue

                in_path = os.path.join(root, fname)
                rel = os.path.relpath(root, db_dir)
                out_subdir = os.path.join(out_dir, rel)
                os.makedirs(out_subdir, exist_ok=True)
                out_path = os.path.join(out_subdir, 'de_' + fname)

                # 若文件已是明文 SQLite，直接复制
                try:
                    with open(in_path, 'rb') as f:
                        header = f.read(6)
                    if header[:6] == b'SQLite':
                        shutil.copy2(in_path, out_path)
                        results.append({"in": in_path, "out": out_path, "skipped": True})
                        continue
                except Exception:
                    pass

                # 确定本文件对应的密钥
                file_key = single_key
                if salt_to_key is not None:
                    try:
                        with open(in_path, 'rb') as f:
                            file_salt = f.read(16).hex()
                        file_key = salt_to_key.get(file_salt)
                        if not file_key:
                            errors.append({"in": in_path,
                                           "error": "未找到对应密钥（salt 不匹配）"})
                            continue
                    except Exception as e:
                        errors.append({"in": in_path, "error": str(e)})
                        continue

                if not file_key:
                    errors.append({"in": in_path, "error": "无可用密钥"})
                    continue

                ok, result = decrypt(file_key, in_path, out_path)
                if ok:
                    results.append({"in": in_path, "out": out_path})
                else:
                    errors.append({"in": in_path, "error": str(result)})

        _out({
            "success":   True,
            "decrypted": len(results),
            "failed":    len(errors),
            "results":   results,
            "errors":    errors,
            "out_dir":   out_dir,
        })

    except ImportError as e:
        _out({"success": False, "error": f"PyWxDump 未找到: {e}"})
    except Exception as e:
        _out({"success": False, "error": str(e)})


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def main():
    args = sys.argv[1:]
    if not args:
        _out({"success": False, "error": "缺少命令参数"})
        return

    cmd = args[0]

    if cmd == 'get_key':
        cmd_get_key()

    elif cmd == 'decrypt':
        if len(args) < 4:
            _out({"success": False, "error": "用法: decrypt <key> <db_path> <out_path>"})
            return
        cmd_decrypt(args[1], args[2], args[3])

    elif cmd == 'decrypt_dir':
        if len(args) < 4:
            _out({"success": False, "error": "用法: decrypt_dir <key_or_json> <db_dir> <out_dir>"})
            return
        cmd_decrypt_dir(args[1], args[2], args[3])

    else:
        _out({"success": False, "error": f"未知命令: {cmd}"})


if __name__ == '__main__':
    main()
