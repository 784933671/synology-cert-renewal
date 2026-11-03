from __future__ import annotations

import asyncio
import json
import re

METHODS = frozenset({"status", "settings.get", "settings.update", "security.update", "run", "renew", "check", "failures.list", "failures.get", "auth.code.send"})
ERRORS = {
    "validation": (400, "配置内容不符合要求，请检查填写项"),
    "invalid_request": (400, "请求格式不正确"),
    "conflict": (409, "当前有未完成的恢复操作，暂时不能修改此配置"),
    "busy": (409, "证书任务正在执行，请稍后重试"),
    "stale_revision": (409, "配置已被其他操作更新，请刷新后重新修改"),
    "not_found": (404, "请求的记录不存在"),
    "unavailable": (503, "群晖执行器暂不可用，请稍后重试"),
    "internal": (502, "群晖执行器未能完成操作，请查看脱敏运行记录"),
}
SECRET_KEYS = re.compile(r"(?:secret.?id|secret.?key|password|passwd|token|private.?key|credential|authorization)", re.I)
SECRET_TEXT = re.compile(r"((?:Tencent_SecretId|Tencent_SecretKey|SecretId|SecretKey|password|authorization)\s*[=:]\s*)[^\s,;]+", re.I)


class BridgeError(Exception):
    def __init__(self, code):
        self.code = code if code in ERRORS else "internal"
        self.status, self.message = ERRORS[self.code]
        super().__init__(self.message)


def safe_data(value, depth=0):
    if depth > 20:
        raise BridgeError("internal")
    if isinstance(value, dict):
        return {key: safe_data(item, depth + 1) for key, item in value.items()
                if isinstance(key, str) and (key in {"secret_id_configured", "secret_key_configured"} or not SECRET_KEYS.search(key))}
    if isinstance(value, list):
        return [safe_data(item, depth + 1) for item in value]
    if isinstance(value, str):
        return SECRET_TEXT.sub(r"\1[已隐藏]", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise BridgeError("internal")


class BridgeClient:
    def __init__(self, socket_path, timeout=60):
        self.socket_path = socket_path
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(4)

    async def call(self, method, params=None):
        if method not in METHODS:
            raise BridgeError("invalid_request")
        encoded = json.dumps({"method": method, "params": params or {}}, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
        if len(encoded) > 65536:
            raise BridgeError("validation")

        async def exchange():
            async with self.semaphore:
                reader, writer = await asyncio.open_unix_connection(self.socket_path, limit=2 * 1024 * 1024 + 1)
                try:
                    writer.write(encoded)
                    await writer.drain()
                    line = await reader.readline()
                    if not line.endswith(b"\n") or len(line) > 2 * 1024 * 1024:
                        raise BridgeError("internal")
                    response = json.loads(line)
                    if not isinstance(response, dict) or type(response.get("ok")) is not bool:
                        raise BridgeError("internal")
                    if not response["ok"]:
                        error = response.get("error", {})
                        raise BridgeError(error.get("code", "internal") if isinstance(error, dict) else "internal")
                    if not isinstance(response.get("data"), dict):
                        raise BridgeError("internal")
                    return safe_data(response["data"])
                finally:
                    writer.close()
                    await writer.wait_closed()

        try:
            return await asyncio.wait_for(exchange(), self.timeout)
        except BridgeError:
            raise
        except (OSError, asyncio.TimeoutError):
            raise BridgeError("unavailable") from None
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise BridgeError("internal") from None
