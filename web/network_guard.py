"""只管理本服务端口的专用链，不刷新 DSM 或 Docker 的规则。"""
import ipaddress
import shlex
import subprocess


class GuardError(Exception):
    pass


def validate_network(bind, networks, denied, port):
    address = ipaddress.IPv4Address(bind)
    private = [ipaddress.ip_network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if not any(address in block for block in private):
        raise ValueError('必须绑定明确的内网 IPv4 地址')
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('管理端口无效')
    ranges = [ipaddress.IPv4Network(value, strict=True) for value in networks]
    if not ranges or not any(address in block for block in ranges):
        raise ValueError('管理地址必须位于内网白名单')
    if any(block.prefixlen < 16 or not any(block.subnet_of(allowed) for allowed in private) for block in ranges):
        raise ValueError('必须指定明确的内网网段，不能允许整个私有地址空间')
    excluded = [ipaddress.IPv4Address(value) for value in denied]
    if not excluded or any(value == address or not any(value in block for block in ranges) for value in excluded):
        raise ValueError('必须指定当前网段的网关地址，并且不能排除 NAS 本身')
    return str(address), [str(block) for block in ranges], [str(value) for value in excluded]


def command(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=15)
    if result.returncode:
        raise GuardError('防火墙操作失败，管理服务保持关闭。')
    return result.stdout


class NetworkGuard:
    def __init__(self, bind, networks, denied, port, run=command):
        self.bind, self.networks, self.denied = validate_network(bind, networks, denied, port)
        self.port, self.run = port, run

    def desired(self, version, hook='INPUT'):
        chain = 'CERTWEB_INPUT' if version == 4 else 'CERTWEB6_INPUT'
        jump = ['-A', hook]
        if version == 4:
            jump += ['-d', self.bind + '/32']
        jump += ['-p', 'tcp', '-m', 'tcp', '--dport', str(self.port), '-j', chain]
        rules = []
        if version == 4:
            rules += [['-A', chain, '-s', value + '/32', '-j', 'DROP'] for value in self.denied]
            rules += [['-A', chain, '-s', value, '-j', 'ACCEPT'] for value in self.networks]
        rules.append(['-A', chain, '-j', 'DROP'])
        return chain, jump, rules

    def snapshot(self, version):
        binary = '/usr/bin/iptables' if version == 4 else '/usr/bin/ip6tables'
        lines = self.run([binary, '-w', '5', '-S']).splitlines()
        return binary, [shlex.split(line) for line in lines if line.strip()]

    @staticmethod
    def hook(snapshot):
        # DSM 将针对 INPUT 的写命令重定向到较晚的 DEFAULT_INPUT。
        # 使用实际最先跳入的 INPUT_FIREWALL，并核验该跳转不可绕过。
        if ['-N', 'INPUT_FIREWALL'] in snapshot:
            inputs = [r for r in snapshot if r[:2] == ['-A', 'INPUT']]
            if not inputs or inputs[0] != ['-A', 'INPUT', '-j', 'INPUT_FIREWALL']:
                raise GuardError('DSM 防火墙入口顺序未知，管理服务保持关闭。')
            return 'INPUT_FIREWALL'
        return 'INPUT'

    def valid(self):
        for version in (4, 6):
            _, snapshot = self.snapshot(version)
            try:
                hook = self.hook(snapshot)
            except GuardError:
                return False
            chain, jump, rules = self.desired(version, hook)
            inputs = [r for r in snapshot if r[:2] == ['-A', hook]]
            existing = [r for r in snapshot if r[:2] == ['-A', chain]]
            references = [r for r in snapshot if r[-2:] == ['-j', chain]]
            if not inputs or inputs[0] != jump or references != [jump] or existing != rules:
                return False
        return True

    def install(self):
        # 调用者须先停止容器；只重建本服务的链，构建完成前不开放监听。
        for version in (4, 6):
            binary, snapshot = self.snapshot(version)
            hook = self.hook(snapshot)
            chain, jump, rules = self.desired(version, hook)
            if ['-N', chain] not in snapshot:
                self.run([binary, '-w', '5', '-N', chain])
            self.run([binary, '-w', '5', '-F', chain])
            for rule in rules:
                self.run([binary, '-w', '5'] + rule)
            for rule in snapshot:
                if rule[0] == '-A' and rule[1] in ('INPUT', 'INPUT_FIREWALL', 'DEFAULT_INPUT') and rule[-2:] == ['-j', chain]:
                    self.run([binary, '-w', '5', '-D'] + rule[1:])
            self.run([binary, '-w', '5', '-I', hook, '1'] + jump[2:])
        if not self.valid():
            raise GuardError('防火墙回读不一致，管理服务保持关闭。')
