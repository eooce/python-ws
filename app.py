#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, time, json, socket, struct, hashlib, base64, asyncio
import logging, ipaddress, subprocess, tempfile, platform, aiohttp
from pathlib import Path
from typing import Tuple, Dict
from aiohttp import web
try:
    import pty
except ImportError:
    pty = None
try:
    import fcntl
except ImportError:
    fcntl = None
try:
    import termios
except ImportError:
    termios = None
try:
    import grpc
    import psutil
    from grpc_tools import protoc
    NEZHA_AVAILABLE = True
except Exception as _nezha_import_err:
    NEZHA_AVAILABLE = False

# ==================== 环境变量 ====================
UUID = os.environ.get('UUID', '7bd180e8-1142-4387-93f5-03e8d750a896')   # 节点UUID
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')    # 仅支持哪吒v1，格式: nezha.xxx.com:8008
NEZHA_KEY = os.environ.get('NEZHA_KEY', '')          # NZ_CLIENT_KEY, 哪吒面板后台命令里获取
DOMAIN = os.environ.get('DOMAIN', '')                # 项目分配的域名或反代后的域名,不包含https://前缀,例如: domain.xxx.com
SUB_PATH = os.environ.get('SUB_PATH', 'sub')         # 节点订阅token
NAME = os.environ.get('NAME', '')                    # 节点名称
WSPATH = os.environ.get('WSPATH', UUID[:8])          # 节点路径
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)  # http和ws端口，默认自动优先获取容器分配的端口
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true' # 自动访问保活,默认关闭,true开启,false关闭,需同时填写DOMAIN变量
DEBUG = os.environ.get('DEBUG', '').lower() == 'true' # 保持默认,调试使用,true开启调试

# 全局变量
VERSION = 'python-9.9.9'  # nezha版本号
REPORT_DELAY = 4          # 状态上报间隔（秒）
RETRY_DELAY = 10          # 重连间隔（秒）
IP_REPORT_PERIOD = 1800   # IP上报周期（秒）
NETWORK_TIMEOUT = 5       # 普通网络超时（秒）
# TLS 端口列表
TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
CurrentDomain = DOMAIN
CurrentPort = 443
Tls = 'tls'
ISP = ''

# dns server
DNS_SERVERS = ['8.8.4.4', '1.1.1.1']
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
]

# 日志级别
log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 禁用访问,连接等日志
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)
logging.getLogger('aiohttp.websocket').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


# 工具函数 
def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None

def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    return any(host_lower == blocked or host_lower.endswith('.' + blocked)
              for blocked in BLOCKED_DOMAINS)

async def get_isp():
    global ISP
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ip.sb/geoip',
                                 headers={'User-Agent': 'Mozilla/5.0'},
                                 timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('country_code', '')}-{data.get('isp', '')}".replace(' ', '_')
                    return
    except:
        pass

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://ip-api.com/json',
                                 headers={'User-Agent': 'Mozilla/5.0'},
                                 timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('countryCode', '')}-{data.get('org', '')}".replace(' ', '_')
                    return
    except:
        pass

    ISP = 'Unknown'

async def get_ip():
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api-ipv4.ip.sb/ip', timeout=5) as resp:
                    if resp.status == 200:
                        ip = await resp.text()
                        CurrentDomain = ip.strip()
                        Tls = 'none'
                        CurrentPort = PORT
        except Exception as e:
            logger.error(f'Failed to get IP: {e}')
            CurrentDomain = 'change-your-domain.com'
            Tls = 'tls'
            CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443

async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except:
        pass

    for dns_server in DNS_SERVERS:
        try:
            async with aiohttp.ClientSession() as session:
                url = f'https://dns.google/resolve?name={host}&type=A'
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('Status') == 0 and data.get('Answer'):
                            for answer in data['Answer']:
                                if answer.get('type') == 1:
                                    return answer.get('data')
        except:
            continue

    return host  # 如果解析失败，返回原始域名


# 代理处理 
class ProxyHandler:
    def __init__(self, uuid: str):
        self.uuid = uuid
        self.uuid_bytes = bytes.fromhex(uuid)

    async def handle_vless(self, websocket, first_msg: bytes) -> bool:
        """处理VLS协议"""
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False

            # 验证UUID
            if first_msg[1:17] != self.uuid_bytes:
                return False

            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False

            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1

            # 解析地址
            host = ''
            if atyp == 1:  # IPv4
                if i + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:  # 域名
                if i >= len(first_msg):
                    return False
                host_len = first_msg[i]
                i += 1
                if i + host_len > len(first_msg):
                    return False
                host = first_msg[i:i+host_len].decode()
                i += host_len
            elif atyp == 3:  # IPv6
                if i + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                              for j in range(i, i+16, 2))
                i += 16
            else:
                return False

            if is_blocked_domain(host):
                await websocket.close()
                return False

            await websocket.send_bytes(bytes([0, 0]))

            resolved_host = await resolve_host(host)

            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)

                # 发送剩余数据
                if i < len(first_msg):
                    writer.write(first_msg[i:])
                    await writer.drain()

                # 双向转发
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass

                await asyncio.gather(
                    forward_ws_to_tcp(),
                    forward_tcp_to_ws()
                )

            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")

            return True

        except Exception as e:
            if DEBUG:
                logger.error(f"VLESS handler error: {e}")
            return False

    async def handle_trojan(self, websocket, first_msg: bytes) -> bool:
        """处理Tro协议"""
        try:
            if len(first_msg) < 58:
                return False

            received_hash_bytes = first_msg[:56]

            # 验证密码 - 支持标准UUID和无短横线UUID
            hash_obj1 = hashlib.sha224()
            hash_obj1.update(self.uuid.encode())
            expected_hash_hex1 = hash_obj1.hexdigest()

            # 尝试使用标准UUID（带短横线）
            standard_uuid = UUID
            hash_obj2 = hashlib.sha224()
            hash_obj2.update(standard_uuid.encode())
            expected_hash_hex2 = hash_obj2.hexdigest()

            # 转换为hex字符串进行比较
            received_hash_hex = received_hash_bytes.decode('ascii', errors='ignore')

            # 检查是否匹配任一UUID格式
            if received_hash_hex != expected_hash_hex1 and received_hash_hex != expected_hash_hex2:
                return False

            offset = 56
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2

            cmd = first_msg[offset]
            if cmd != 1:
                return False
            offset += 1

            atyp = first_msg[offset]
            offset += 1

            # 解析地址
            host = ''
            if atyp == 1:  # IPv4
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:  # 域名
                host_len = first_msg[offset]
                offset += 1
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:  # IPv6
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                              for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False

            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2

            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2

            if is_blocked_domain(host):
                await websocket.close()
                return False

            # 连接目标
            resolved_host = await resolve_host(host)

            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)

                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()

                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass

                await asyncio.gather(
                    forward_ws_to_tcp(),
                    forward_tcp_to_ws()
                )

            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")

            return True

        except Exception as e:
            if DEBUG:
                logger.error(f"Tro handler error: {e}")
            return False

    async def handle_shadowsocks(self, websocket, first_msg: bytes) -> bool:
        """处理ss协议"""
        try:
            if len(first_msg) < 7:
                return False

            offset = 0
            atyp = first_msg[offset]
            offset += 1

            # 解析地址
            host = ''
            if atyp == 1:  # IPv4
                if offset + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:  # 域名
                if offset >= len(first_msg):
                    return False
                host_len = first_msg[offset]
                offset += 1
                if offset + host_len > len(first_msg):
                    return False
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:  # IPv6
                if offset + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                              for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False

            if offset + 2 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2

            if is_blocked_domain(host):
                await websocket.close()
                return False

            # 连接目标
            resolved_host = await resolve_host(host)

            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)

                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()

                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass

                await asyncio.gather(
                    forward_ws_to_tcp(),
                    forward_tcp_to_ws()
                )

            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")

            return True

        except Exception as e:
            if DEBUG:
                logger.error(f"Shadowsocks handler error: {e}")
            return False


# HTTP/WebSocket 处理 
async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    CUUID = UUID.replace('-', '')
    path = request.path

    if f'/{WSPATH}' not in path:
        await ws.close()
        return ws

    proxy = ProxyHandler(CUUID)

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws

        msg_data = first_msg.data

        # 尝试VLS
        if len(msg_data) > 17 and msg_data[0] == 0:
            if await proxy.handle_vless(ws, msg_data):
                return ws

        # 尝试Tro
        if len(msg_data) >= 58:
            if await proxy.handle_trojan(ws, msg_data):
                return ws

        # 尝试ss
        if len(msg_data) > 0 and msg_data[0] in (1, 3, 4):
            if await proxy.handle_shadowsocks(ws, msg_data):
                return ws

        await ws.close()

    except asyncio.TimeoutError:
        await ws.close()
    except Exception as e:
        if DEBUG:
            logger.error(f"WebSocket handler error: {e}")
        await ws.close()

    return ws

async def http_handler(request):
    if request.path == '/':
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                content = f.read()
            return web.Response(text=content, content_type='text/html')
        except:
            return web.Response(text='Hello world!', content_type='text/html')

    elif request.path == f'/{SUB_PATH}':
        await get_isp()
        await get_ip()

        name_part = f"{NAME}-{ISP}" if NAME else ISP
        tls_param = 'tls' if Tls == 'tls' else 'none'
        ss_tls_param = 'tls;' if Tls == 'tls' else ''

        # 生成配置链接
        vless_url = f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none&security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        trojan_url = f"trojan://{UUID}@{CurrentDomain}:{CurrentPort}?security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"

        ss_method_password = base64.b64encode(f"none:{UUID}".encode()).decode()
        ss_url = f"ss://{ss_method_password}@{CurrentDomain}:{CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{CurrentDomain};path%3D%2F{WSPATH};{ss_tls_param}sni%3D{CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#{name_part}"

        subscription = f"{vless_url}\n{trojan_url}\n{ss_url}"
        base64_content = base64.b64encode(subscription.encode()).decode()

        return web.Response(text=base64_content + '\n', content_type='text/plain')

    return web.Response(status=404, text='Not Found\n')


# ==================== 保活与清理 ====================
async def add_access_task():
    if not AUTO_ACCESS or not DOMAIN:
        return

    full_url = f"https://{DOMAIN}/{SUB_PATH}"
    try:
        async with aiohttp.ClientSession() as session:
            await session.post("https://oooo.serv00.net/add-url",
                             json={"url": full_url},
                             headers={'Content-Type': 'application/json'})
        logger.info('Automatic Access Task added successfully')
    except:
        pass

def cleanup_files():
    for file in ['npm', 'config.yaml']:
        try:
            if os.path.exists(file):
                os.remove(file)
        except:
            pass


# Nezha: TLS 检测 
def should_use_tls(server: str) -> bool:
    parts = server.split(':')
    if len(parts) < 2:
        return False
    try:
        port = int(parts[-1])
        return port in TLS_PORTS
    except ValueError:
        return False

# Nezha: Proto 定义与编译
if NEZHA_AVAILABLE:
    PROTO_CONTENT = '''
syntax = "proto3";
option go_package = "./proto";
package proto;

service NezhaService {
  rpc ReportSystemState(stream State) returns (stream Receipt) {}
  rpc ReportSystemInfo(Host) returns (Receipt) {}
  rpc RequestTask(stream TaskResult) returns (stream Task) {}
  rpc IOStream(stream IOStreamData) returns (stream IOStreamData) {}
  rpc ReportGeoIP(GeoIP) returns (GeoIP) {}
  rpc ReportSystemInfo2(Host) returns (Uint64Receipt) {}
}

message Host {
  string platform = 1;
  string platform_version = 2;
  repeated string cpu = 3;
  uint64 mem_total = 4;
  uint64 disk_total = 5;
  uint64 swap_total = 6;
  string arch = 7;
  string virtualization = 8;
  uint64 boot_time = 9;
  string version = 10;
  repeated string gpu = 11;
}

message State {
  double cpu = 1;
  uint64 mem_used = 2;
  uint64 swap_used = 3;
  uint64 disk_used = 4;
  uint64 net_in_transfer = 5;
  uint64 net_out_transfer = 6;
  uint64 net_in_speed = 7;
  uint64 net_out_speed = 8;
  uint64 uptime = 9;
  double load1 = 10;
  double load5 = 11;
  double load15 = 12;
  uint64 tcp_conn_count = 13;
  uint64 udp_conn_count = 14;
  uint64 process_count = 15;
  repeated State_SensorTemperature temperatures = 16;
  repeated double gpu = 17;
}

message State_SensorTemperature {
  string name = 1;
  double temperature = 2;
}

message Task {
  uint64 id = 1;
  uint64 type = 2;
  string data = 3;
}

message TaskResult {
  uint64 id = 1;
  uint64 type = 2;
  float delay = 3;
  string data = 4;
  bool successful = 5;
}

message Receipt { bool proced = 1; }
message Uint64Receipt { uint64 data = 1; }
message IOStreamData { bytes data = 1; }

message GeoIP {
  bool use6 = 1;
  IP ip = 2;
  string country_code = 3;
  uint64 dashboard_boot_time = 4;
}

message IP {
  string ipv4 = 1;
  string ipv6 = 2;
}
'''

    def compile_proto():
        """动态编译 proto 文件并返回生成的模块"""
        with tempfile.TemporaryDirectory() as tmpdir:
            proto_path = Path(tmpdir) / 'nezha.proto'
            proto_path.write_text(PROTO_CONTENT)
            out_dir = Path(tmpdir) / 'out'
            out_dir.mkdir()
            # 调用 protoc
            args = [
                'grpc_tools.protoc',
                f'--proto_path={tmpdir}',
                f'--python_out={out_dir}',
                f'--grpc_python_out={out_dir}',
                str(proto_path),
            ]
            protoc.main(args)
            # 动态导入生成的模块
            sys.path.insert(0, str(out_dir))
            import nezha_pb2 as pb2
            import nezha_pb2_grpc as pb2_grpc
            return pb2, pb2_grpc

    # 编译并导入
    try:
        pb2, pb2_grpc = compile_proto()
    except Exception as e:
        logger.warning(f'Failed to compile proto: {e}')
        NEZHA_AVAILABLE = False


# Nezha: gRPC 元数据
def build_metadata():
    return (
        ('client-secret', NEZHA_KEY),
        ('client-uuid', UUID),
        ('client_secret', NEZHA_KEY),
        ('client_uuid', UUID),
    )

# Nezha: 系统监控
if NEZHA_AVAILABLE:
    EXCLUDE_INTERFACES = {'lo', 'tun', 'docker', 'veth', 'br-', 'vmbr', 'vnet', 'kube', 'Meta', 'tailscale', 'fw', 'tap'}
    EXPECT_FS_TYPES = {'apfs', 'ext4', 'ext3', 'ext2', 'f2fs', 'reiserfs', 'jfs', 'bcachefs',
                       'btrfs', 'fuseblk', 'zfs', 'simfs', 'ntfs', 'fat32', 'exfat', 'xfs', 'fuse.rclone'}

    def should_exclude_interface(name: str) -> bool:
        return any(ex in name for ex in EXCLUDE_INTERFACES)

    def get_arch() -> str:
        arch_map = {
            'x86_64': 'x86_64',
            'AMD64': 'x86_64',
            'aarch64': 'aarch64',
            'arm64': 'aarch64',
            'i386': 'i386',
            'i686': 'i386',
        }
        return arch_map.get(platform.machine(), platform.machine())

    # 网络统计全局变量
    _net_in_transfer = 0
    _net_out_transfer = 0
    _net_in_speed = 0
    _net_out_speed = 0
    _last_net_update = 0

    def update_network_speed():
        global _net_in_transfer, _net_out_transfer, _net_in_speed, _net_out_speed, _last_net_update
        try:
            stats = psutil.net_io_counters(pernic=True)
            inner_in = 0
            inner_out = 0
            for iface, val in stats.items():
                if should_exclude_interface(iface):
                    continue
                inner_in += val.bytes_recv
                inner_out += val.bytes_sent
            now = time.time()
            if _last_net_update > 0:
                diff = now - _last_net_update
                if diff > 0:
                    _net_in_speed = max(0, (inner_in - _net_in_transfer) / diff)
                    _net_out_speed = max(0, (inner_out - _net_out_transfer) / diff)
            _net_in_transfer = inner_in
            _net_out_transfer = inner_out
            _last_net_update = now
        except Exception:
            pass

    def get_host():
        """获取主机信息"""
        system = platform.system()
        if system == 'Linux':
            try:
                import distro
                platform_name = distro.name()
                platform_version = distro.version()
            except ImportError:
                platform_name = system
                platform_version = platform.release()
        else:
            platform_name = system
            platform_version = platform.release()
        # CPU
        try:
            cpu_brand = platform.processor() or 'Unknown CPU'
            physical_cores = psutil.cpu_count(logical=False)
            cpu_str = f"{cpu_brand} {physical_cores} Physical Core"
        except:
            cpu_str = 'Unknown CPU'
        # 内存
        mem = psutil.virtual_memory()
        mem_total = mem.total
        swap = psutil.swap_memory()
        swap_total = swap.total
        # 磁盘
        disk_total = 0
        for part in psutil.disk_partitions():
            if part.fstype and part.fstype.lower() in EXPECT_FS_TYPES:
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disk_total += usage.total
                except:
                    pass
        # 启动时间
        boot_time = int(psutil.boot_time())
        # arch
        arch = get_arch()
        # 构建 Host
        host = pb2.Host()
        host.platform = platform_name
        host.platform_version = platform_version
        host.cpu.append(cpu_str)
        host.mem_total = mem_total
        host.disk_total = disk_total
        host.swap_total = swap_total
        host.arch = arch
        host.virtualization = ''
        host.boot_time = boot_time
        host.version = VERSION
        return host

    def get_state():
        """获取当前状态"""
        cpu_percent = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        if sys.platform == 'linux':
            mem_used = max(0, mem.total - mem.free - mem.buffers - mem.cached)
        else:
            mem_used = mem.used
        swap = psutil.swap_memory()
        swap_used = swap.used
        # 磁盘
        disk_used = 0
        for part in psutil.disk_partitions():
            if part.fstype and part.fstype.lower() in EXPECT_FS_TYPES:
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disk_used += usage.used
                except:
                    pass
        # 网络
        global _net_in_transfer, _net_out_transfer, _net_in_speed, _net_out_speed
        net_in_transfer = _net_in_transfer
        net_out_transfer = _net_out_transfer
        net_in_speed = int(_net_in_speed)
        net_out_speed = int(_net_out_speed)
        # 负载
        load1, load5, load15 = os.getloadavg() if hasattr(os, 'getloadavg') else (0,0,0)
        # 进程数
        process_count = len(psutil.pids())
        # 连接数
        tcp_conn, udp_conn = get_conn_count()
        # 运行时间
        uptime = int(time.time() - psutil.boot_time())
        # 构建 State
        state = pb2.State()
        state.cpu = cpu_percent
        state.mem_used = mem_used
        state.swap_used = swap_used
        state.disk_used = disk_used
        state.net_in_transfer = net_in_transfer
        state.net_out_transfer = net_out_transfer
        state.net_in_speed = net_in_speed
        state.net_out_speed = net_out_speed
        state.uptime = uptime
        state.load1 = load1
        state.load5 = load5
        state.load15 = load15
        state.tcp_conn_count = tcp_conn
        state.udp_conn_count = udp_conn
        state.process_count = process_count
        return state

    def get_conn_count() -> Tuple[int, int]:
        """读取 /proc/net/tcp 等获取连接数（仅 Linux）"""
        if sys.platform != 'linux':
            return 0, 0
        tcp = 0
        udp = 0
        for proto in ['tcp', 'tcp6']:
            try:
                with open(f'/proc/net/{proto}', 'r') as f:
                    lines = f.readlines()
                    tcp += max(0, len(lines) - 1)
            except:
                pass
        for proto in ['udp', 'udp6']:
            try:
                with open(f'/proc/net/{proto}', 'r') as f:
                    lines = f.readlines()
                    udp += max(0, len(lines) - 1)
            except:
                pass
        return tcp, udp


    # Nezha: GeoIP 
    _cached_ip = ''
    _geo_query_ip_changed = True
    _prev_dashboard_boot_time = 0

    async def fetch_ip() -> Dict[str, str]:
        """获取公网 IPv4 和 IPv6"""
        ipv4_endpoints = [
            'https://ipv4.ip.sb/ip',
            'https://blog.cloudflare.com/cdn-cgi/trace',
            'https://developers.cloudflare.com/cdn-cgi/trace',
        ]
        ipv6_endpoints = [
            'https://ipv6.ip.sb/ip',
            'https://blog.cloudflare.com/cdn-cgi/trace',
            'https://developers.cloudflare.com/cdn-cgi/trace',
        ]

        async def fetch_from_endpoints(endpoints, family):
            for url in endpoints:
                try:
                    connector = aiohttp.TCPConnector(family=family)
                    async with aiohttp.ClientSession(connector=connector) as session:
                        async with session.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'}) as resp:
                            text = await resp.text()
                            ip = parse_ip_from_response(text, family)
                            if ip:
                                return ip
                except:
                    continue
            return ''

        def parse_ip_from_response(text, family):
            text = text.strip()
            try:
                if family == socket.AF_INET and is_ipv4(text):
                    return text
                if family == socket.AF_INET6 and is_ipv6(text):
                    return text
            except:
                pass
            for line in text.splitlines():
                if line.startswith('ip='):
                    ip = line[3:].strip()
                    if family == socket.AF_INET and is_ipv4(ip):
                        return ip
                    if family == socket.AF_INET6 and is_ipv6(ip):
                        return ip
            return ''

        def is_ipv4(ip):
            try:
                socket.inet_pton(socket.AF_INET, ip)
                return True
            except:
                return False

        def is_ipv6(ip):
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except:
                return False

        ipv4, ipv6 = await asyncio.gather(
            fetch_from_endpoints(ipv4_endpoints, socket.AF_INET),
            fetch_from_endpoints(ipv6_endpoints, socket.AF_INET6),
        )
        global _cached_ip, _geo_query_ip_changed
        new_ip = ipv6 or ipv4
        if new_ip and new_ip != _cached_ip:
            _geo_query_ip_changed = True
            _cached_ip = new_ip
        return {'ipv4': ipv4, 'ipv6': ipv6}

    async def report_geoip(stub, metadata, force_update: bool) -> bool:
        """上报 GeoIP"""
        global _geo_query_ip_changed, _prev_dashboard_boot_time
        ips = await fetch_ip()
        if not ips['ipv4'] and not ips['ipv6']:
            return False
        if not _geo_query_ip_changed and not force_update:
            return True
        geo_req = pb2.GeoIP()
        geo_req.use6 = False
        geo_req.ip.ipv4 = ips['ipv4'] or ''
        geo_req.ip.ipv6 = ips['ipv6'] or ''
        try:
            resp = await stub.ReportGeoIP(geo_req, metadata=metadata, timeout=NETWORK_TIMEOUT)
            if resp:
                _prev_dashboard_boot_time = resp.dashboard_boot_time or 0
                _geo_query_ip_changed = False
                return True
        except Exception:
            pass
        return False


    # Nezha: 任务处理
    TASK_TERMINAL = 8
    TASK_FM = 11

    # FM 二进制协议标识
    FM_NZFN = b'\x4e\x5a\x46\x4e'  # 目录列表头
    FM_NZTD = b'\x4e\x5a\x54\x44'  # 文件下载头
    FM_NERR = b'\x4e\x45\x52\x52'  # 错误
    FM_NZUP = b'\x4e\x5a\x55\x50'  # 上传完成

    class TerminalSession:
        """终端会话（支持 PTY 和降级模式）"""
        def __init__(self, stream_id: str, io_stream):
            self.stream_id = stream_id
            self.io_stream = io_stream
            self.proc = None
            self.loop = asyncio.get_event_loop()
            self.pty = None
            self.keepalive_task = None
            self.closed = False

        async def start(self):
            """启动 shell"""
            try:
                import ptyprocess
                self.proc = ptyprocess.PtyProcessUnicode.spawn(
                    [os.environ.get('SHELL', '/bin/bash')],
                    cwd=os.path.expanduser('~'),
                    env={**os.environ, 'TERM': 'xterm'},
                )
                self.pty = self.proc
                self.loop.create_task(self._read_pty())
            except ImportError:
                self.proc = await asyncio.create_subprocess_exec(
                    os.environ.get('SHELL', '/bin/bash'),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=os.path.expanduser('~'),
                    env={**os.environ, 'TERM': 'dumb'},
                )
                self.loop.create_task(self._read_subprocess())
            self.keepalive_task = self.loop.create_task(self._keepalive())
            await self._send_streamid()

        async def _send_streamid(self):
            data = b'\xff\x05\xff\x05' + self.stream_id.encode()
            await self.io_stream.write(pb2.IOStreamData(data=data))

        async def _read_pty(self):
            """读取 PTY 输出并发送到 IOStream"""
            try:
                while not self.closed:
                    data = self.proc.read(4096)
                    if not data:
                        break
                    await self.io_stream.write(pb2.IOStreamData(data=data.encode()))
            except Exception:
                pass
            finally:
                await self.close()

        async def _read_subprocess(self):
            """读取子进程输出"""
            try:
                while not self.closed:
                    for fd in [self.proc.stdout, self.proc.stderr]:
                        data = await fd.read(4096)
                        if data:
                            await self.io_stream.write(pb2.IOStreamData(data=data))
            except Exception:
                pass
            finally:
                await self.close()

        async def write(self, data: bytes):
            """写入数据到 shell"""
            if self.closed:
                return
            if self.pty:
                self.pty.write(data.decode(errors='ignore'))
            else:
                self.proc.stdin.write(data)
                await self.proc.stdin.drain()

        async def resize(self, cols: int, rows: int):
            """调整窗口大小（仅 PTY）"""
            if self.pty and hasattr(self.pty, 'setwinsize'):
                self.pty.setwinsize(rows, cols)

        async def _keepalive(self):
            """每 30 秒发送空数据"""
            while not self.closed:
                await asyncio.sleep(30)
                try:
                    await self.io_stream.write(pb2.IOStreamData(data=b''))
                except:
                    break

        async def close(self):
            if self.closed:
                return
            self.closed = True
            if self.keepalive_task:
                self.keepalive_task.cancel()
            if self.pty:
                self.pty.terminate()
            elif self.proc:
                self.proc.terminate()
                await self.proc.wait()
            try:
                await self.io_stream.done_writing()
            except:
                pass

    async def handle_terminal_task(task, stub, metadata):
        """处理终端任务"""
        try:
            terminal = json.loads(task.data)
        except:
            return
        stream_id = terminal.get('StreamID', '')
        if not stream_id:
            return
        io_stream = stub.IOStream(metadata=metadata)
        session = TerminalSession(stream_id, io_stream)
        await session.start()
        try:
            async for msg in io_stream:
                data = msg.data
                if not data:
                    continue
                if data[0] == 0:  # stdin
                    await session.write(data[1:])
                elif data[0] == 1:  # resize
                    try:
                        resize_info = json.loads(data[1:].decode())
                        cols = resize_info.get('Cols', 80)
                        rows = resize_info.get('Rows', 40)
                        await session.resize(cols, rows)
                    except:
                        pass
        except Exception:
            pass
        finally:
            await session.close()

    class FMSession:
        """文件管理会话"""
        def __init__(self, stream_id: str, io_stream):
            self.stream_id = stream_id
            self.io_stream = io_stream
            self.upload_state = None
            self.keepalive_task = None
            self.closed = False

        async def start(self):
            await self._send_streamid()
            self.keepalive_task = asyncio.create_task(self._keepalive())

        async def _send_streamid(self):
            data = b'\xff\x05\xff\x05' + self.stream_id.encode()
            await self.io_stream.write(pb2.IOStreamData(data=data))

        async def _keepalive(self):
            while not self.closed:
                await asyncio.sleep(30)
                try:
                    await self.io_stream.write(pb2.IOStreamData(data=b''))
                except:
                    break

        async def close(self):
            self.closed = True
            if self.keepalive_task:
                self.keepalive_task.cancel()
            if self.upload_state:
                try:
                    self.upload_state['write_stream'].close()
                except:
                    pass

        async def handle_data(self, data: bytes):
            """处理接收到的数据（FM 协议）"""
            if self.upload_state:
                self.upload_state['write_stream'].write(data)
                self.upload_state['received'] += len(data)
                if self.upload_state['received'] >= self.upload_state['file_size']:
                    self.upload_state['write_stream'].close()
                    await self.io_stream.write(pb2.IOStreamData(data=FM_NZUP))
                    self.upload_state = None
                return

            if not data:
                return
            cmd = data[0]
            payload = data[1:]
            if cmd == 0:  # 列目录
                await self._list_dir(payload.decode())
            elif cmd == 1:  # 下载文件
                await self._download_file(payload.decode())
            elif cmd == 2:  # 上传文件
                await self._start_upload(payload)

        async def _list_dir(self, dir_path: str):
            """列目录并发送 NZFN 头"""
            try:
                entries = os.listdir(dir_path)
                path_buf = dir_path.encode()
                path_len = struct.pack('>I', len(path_buf))
                parts = [FM_NZFN, path_len, path_buf]
                for name in entries:
                    full = os.path.join(dir_path, name)
                    is_dir = 1 if os.path.isdir(full) else 0
                    name_buf = name.encode()
                    parts.append(bytes([is_dir, len(name_buf) & 0xFF]))
                    parts.append(name_buf)
                await self.io_stream.write(pb2.IOStreamData(data=b''.join(parts)))
            except Exception as e:
                home = os.path.expanduser('~')
                if dir_path != home:
                    await self._list_dir(home)
                else:
                    await self._send_error(str(e))

        async def _download_file(self, file_path: str):
            """下载文件"""
            try:
                size = os.path.getsize(file_path)
                if size <= 0:
                    await self._send_error('requested file is empty')
                    return
                size_buf = struct.pack('>Q', size)
                await self.io_stream.write(pb2.IOStreamData(data=FM_NZTD + size_buf))
                with open(file_path, 'rb') as f:
                    while True:
                        chunk = f.read(1024*1024)
                        if not chunk:
                            break
                        await self.io_stream.write(pb2.IOStreamData(data=chunk))
            except Exception as e:
                await self._send_error(str(e))

        async def _start_upload(self, payload: bytes):
            """开始接收上传文件"""
            if len(payload) < 9:
                await self._send_error('data is invalid')
                return
            file_size = struct.unpack('>Q', payload[:8])[0]
            file_path = payload[8:].decode()
            try:
                write_stream = open(file_path, 'wb')
                self.upload_state = {
                    'write_stream': write_stream,
                    'file_size': file_size,
                    'received': 0,
                }
            except Exception as e:
                await self._send_error(str(e))

        async def _send_error(self, msg: str):
            await self.io_stream.write(pb2.IOStreamData(data=FM_NERR + msg.encode()))

    async def handle_fm_task(task, stub, metadata):
        """处理文件管理任务"""
        try:
            fm_task = json.loads(task.data)
        except:
            return
        stream_id = fm_task.get('StreamID', '')
        if not stream_id:
            return
        io_stream = stub.IOStream(metadata=metadata)
        session = FMSession(stream_id, io_stream)
        await session.start()
        try:
            async for msg in io_stream:
                data = msg.data
                if not data:
                    continue
                await session.handle_data(data)
        except Exception:
            pass
        finally:
            await session.close()

    def dispatch_task(task, stub, metadata):
        """分发任务"""
        if task.type == TASK_TERMINAL:
            asyncio.create_task(handle_terminal_task(task, stub, metadata))
        elif task.type == TASK_FM:
            asyncio.create_task(handle_fm_task(task, stub, metadata))


    # Nezha:主循环
    async def nezha_main_loop():
        use_tls = should_use_tls(NEZHA_SERVER)
        if use_tls:
            credentials = grpc.ssl_channel_credentials()
        else:
            credentials = grpc.local_channel_credentials()

        last_report_host = 0
        last_report_ip = 0
        geoip_reported = False
        prev_dashboard_boot_time = 0

        while True:
            try:
                channel = grpc.aio.insecure_channel(NEZHA_SERVER) if not use_tls else grpc.aio.secure_channel(NEZHA_SERVER, credentials)
                stub = pb2_grpc.NezhaServiceStub(channel)
                metadata = build_metadata()

                # 1. 上报主机信息
                host_info = get_host()
                try:
                    receipt = await stub.ReportSystemInfo2(host_info, metadata=metadata, timeout=NETWORK_TIMEOUT)
                    dashboard_boot_time = receipt.data or 0
                    logger.info('✅ nz is running')
                except Exception as e:
                    raise e

                # 判断 dashboard 是否重启
                global _geo_query_ip_changed
                if geoip_reported and prev_dashboard_boot_time != 0 and dashboard_boot_time != prev_dashboard_boot_time:
                    geoip_reported = False
                    _geo_query_ip_changed = True
                    logger.info('[Agent] 重新上报 GeoIP')
                prev_dashboard_boot_time = dashboard_boot_time

                # 2. 建立 RequestTask 流
                task_stream = stub.RequestTask(metadata=metadata)

                # 3. 建立 ReportSystemState 流
                state_stream = stub.ReportSystemState(metadata=metadata)

                # 任务接收协程
                async def task_receiver():
                    try:
                        async for task in task_stream:
                            dispatch_task(task, stub, metadata)
                    except Exception:
                        pass
                    finally:
                        state_stream.cancel()

                # 状态上报协程
                async def state_sender():
                    nonlocal last_report_host, last_report_ip, geoip_reported
                    try:
                        while True:
                            update_network_speed()
                            state = get_state()
                            await state_stream.write(state)
                            try:
                                await state_stream.read()
                            except:
                                break

                            now = time.time()
                            if now - last_report_host > 30 * 60:
                                host_refresh = get_host()
                                try:
                                    await stub.ReportSystemInfo2(host_refresh, metadata=metadata, timeout=10)
                                except:
                                    pass
                                last_report_host = now

                            if (now - last_report_ip > IP_REPORT_PERIOD) or not geoip_reported:
                                if await report_geoip(stub, metadata, not geoip_reported):
                                    last_report_ip = now
                                    geoip_reported = True

                            await asyncio.sleep(REPORT_DELAY)
                    except Exception:
                        pass
                    finally:
                        task_stream.cancel()

                await asyncio.gather(task_receiver(), state_sender(), return_exceptions=True)

            except Exception as e:
                logger.error(f'[Agent] 连接错误: {e}', file=sys.stderr)

            await asyncio.sleep(RETRY_DELAY)

# 主函数
async def main():
    # 如果 NEZHA_SERVER 和 NEZHA_KEY 存在，先启动 nezha
    if NEZHA_AVAILABLE and NEZHA_SERVER and NEZHA_KEY:
        asyncio.create_task(nezha_main_loop())
        # logger.info('Nezha agent started')
    elif not NEZHA_AVAILABLE:
        logger.warning(f'Nezha dependencies not available, skipping: {_nezha_import_err}')
    else:
        logger.info('nezha varibles is empty, skipping')

    app = web.Application()

    # 路由
    app.router.add_get('/', http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)

    # 启动服务
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()
    await get_ip()

    logger.info(f"🌐 Public IP/Domain: {CurrentDomain}")
    logger.info(f"✅ server is running on port {PORT}")
    async def delayed_cleanup():
        await asyncio.sleep(180)
        cleanup_files()

    asyncio.create_task(delayed_cleanup())

    await add_access_task()

    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
        cleanup_files()
