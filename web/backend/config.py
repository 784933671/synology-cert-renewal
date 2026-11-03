from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))


def private_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and any(address in network for network in PRIVATE_NETWORKS)


@dataclass(frozen=True)
class Config:
    data_dir: Path = Path("/data")
    bridge_socket: str = "/bridge/certweb.sock"
    static_dir: Path = Path("/app/static")
    allowed_networks: tuple[str, ...] = ()
    denied_addresses: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ("localhost:18443", "127.0.0.1:18443")
    origin: str = "https://localhost:18443"
    bridge_timeout: float = 60
    body_timeout: float = 10
    request_timeout: float = 70
    networks: tuple = field(init=False, repr=False)

    def __post_init__(self):
        networks = []
        for value in self.allowed_networks:
            network = ipaddress.ip_network(value, strict=True)
            if network.version != 4 or not any(network.subnet_of(item) for item in PRIVATE_NETWORKS):
                raise ValueError("仅允许明确的 RFC1918 局域网 IPv4 网段")
            networks.append(network)
        object.__setattr__(self, "networks", tuple(networks))
        for value in self.denied_addresses:
            if not private_ipv4(value):
                raise ValueError("拒绝来源必须是明确的局域网 IPv4 地址")
        for host in self.allowed_hosts:
            parsed = urlsplit("https://" + host)
            if (not host or host != host.lower() or "*" in host or parsed.username or
                    parsed.password or parsed.path or parsed.query or parsed.fragment or
                    not parsed.hostname or any(char.isspace() for char in host)):
                raise ValueError("Host 白名单必须为精确的主机名与端口")
            _ = parsed.port
        origin = urlsplit(self.origin)
        if (origin.scheme != "https" or origin.netloc not in self.allowed_hosts or
                origin.path or origin.query or origin.fragment):
            raise ValueError("管理页面来源必须是 Host 白名单内的 HTTPS 地址")

    @classmethod
    def from_env(cls):
        def items(name, default=""):
            return tuple(value.strip().lower() for value in os.getenv(name, default).split(",") if value.strip())
        return cls(
            data_dir=Path(os.getenv("CERTWEB_DATA_DIR", "/data")),
            bridge_socket=os.getenv("CERTWEB_BRIDGE_SOCKET", "/bridge/certweb.sock"),
            static_dir=Path(os.getenv("CERTWEB_STATIC_DIR", "/app/static")),
            allowed_networks=items("CERTWEB_ALLOWED_NETWORKS"),
            denied_addresses=items("CERTWEB_DENIED_ADDRESSES"),
            allowed_hosts=items("CERTWEB_ALLOWED_HOSTS", "localhost:18443,127.0.0.1:18443"),
            origin=os.getenv("CERTWEB_ORIGIN", "https://localhost:18443"),
        )

    def allows_peer(self, value: str, path: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        if address.version != 4:
            return False
        if str(address) in self.denied_addresses:
            return False
        # 唯一的回环例外是健康检查，不允许回环来源操作业务 API。
        if address == ipaddress.ip_address("127.0.0.1") and path == "/healthz":
            return True
        return any(address in network for network in self.networks)
