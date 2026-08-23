import ipaddress
import os
from dataclasses import dataclass


def _networks(value):
    networks = []
    for item in value.split(","):
        item = item.strip()
        if item:
            networks.append(ipaddress.ip_network(item, strict=False))
    return tuple(networks)


@dataclass(frozen=True)
class Config:
    reasoning_interval_sec: int
    reasoning_effort: str
    ignore_networks: tuple
    allow_networks: tuple
    state_dir: str
    access_log_path: str
    scanner_result_path: str
    moonshot_api_key: str
    moonshot_base_url: str
    moonshot_model: str

    @classmethod
    def from_env(cls):
        interval = int(os.getenv("K3DF_REASONING_INTERVAL_SEC", "10"))
        if interval < 1:
            raise ValueError("K3DF_REASONING_INTERVAL_SEC must be at least 1")
        return cls(
            reasoning_interval_sec=interval,
            reasoning_effort=os.getenv("K3DF_REASONING_EFFORT", "low"),
            ignore_networks=_networks(os.getenv("K3DF_IGNORE_NETWORKS", "10.8.8.0/24")),
            allow_networks=_networks(os.getenv("K3DF_ALLOW_NETWORKS", "")),
            state_dir=os.getenv("K3DF_STATE_DIR", "/state"),
            access_log_path=os.getenv("K3DF_ACCESS_LOG_PATH", "/var/log/nginx/access.log"),
            scanner_result_path=os.getenv("K3DF_SCANNER_RESULT_PATH", "/state/scanner/latest.json"),
            moonshot_api_key=os.getenv("MOONSHOT_API_KEY", ""),
            moonshot_base_url=os.getenv("K3DF_MOONSHOT_BASE_URL", "https://api.moonshot.ai/v1"),
            moonshot_model=os.getenv("K3DF_MOONSHOT_MODEL", "kimi-k3"),
        )
