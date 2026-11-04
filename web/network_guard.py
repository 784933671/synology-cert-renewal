"""只管理本服务端口的专用链，不刷新 DSM 或 Docker 的规则。"""
import hashlib
import ipaddress
import json
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


def restore_command(args, payload):
    result = subprocess.run(args, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=15)
    if result.returncode:
        raise GuardError('防火墙原子修复未确认，管理服务必须关闭。')
    return result.stdout


class NetworkGuard:
    def __init__(self, bind, networks, denied, port, run=command, access_mode='lan', restore=restore_command):
        self.bind, self.networks, self.denied = validate_network(bind, networks, denied, port)
        self.port, self.run = port, run
        self.access_mode = access_mode
        self.last_diagnostic = None
        self.restore = restore

    def desired(self, version, hook='INPUT'):
        if self.access_mode not in ('lan', 'public'):
            raise GuardError('访问模式无效，管理服务保持关闭。')
        chain = 'CERTWEB_INPUT' if version == 4 else 'CERTWEB6_INPUT'
        jump = ['-A', hook]
        if version == 4:
            jump += ['-d', self.bind + '/32']
        jump += ['-p', 'tcp', '-m', 'tcp', '--dport', str(self.port), '-j', chain]
        rules = []
        if version == 4 and self.access_mode == 'public':
            rules.append(['-A', chain, '-j', 'ACCEPT'])
        elif version == 4:
            rules += [['-A', chain, '-s', value + '/32', '-j', 'DROP'] for value in self.denied]
            rules += [['-A', chain, '-s', value, '-j', 'ACCEPT'] for value in self.networks]
        if version == 6 or self.access_mode == 'lan':
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
        inputs = [r for r in snapshot if r[:2] == ['-A', 'INPUT']]
        if any(token in ('-j', '--jump', '-g', '--goto') and rule[index + 1] == 'FIREWALL_RELOADING'
               for rule in inputs for index, token in enumerate(rule[:-1])):
            raise GuardError('DSM 防火墙正在重载，管理服务保持关闭。')
        if ['-N', 'INPUT_FIREWALL'] in snapshot:
            if not inputs or inputs[0] != ['-A', 'INPUT', '-j', 'INPUT_FIREWALL']:
                raise GuardError('DSM 防火墙入口顺序未知，管理服务保持关闭。')
            return 'INPUT_FIREWALL'
        if ['-N', 'DEFAULT_INPUT'] in snapshot:
            raise GuardError('DSM 防火墙入口不完整，管理服务保持关闭。')
        return 'INPUT'

    @staticmethod
    def references(snapshot, chain):
        return [rule for rule in snapshot if any(
            token in ('-j', '--jump', '-g', '--goto') and rule[index + 1] == chain
            for index, token in enumerate(rule[:-1]))]

    def diagnostic(self, version, reason, snapshot=(), hook='unknown', expected=None):
        chain = 'CERTWEB_INPUT' if version == 4 else 'CERTWEB6_INPUT'
        entry = [rule for rule in snapshot if rule[:2] == ['-A', 'INPUT']]
        inputs = [rule for rule in snapshot if rule[:2] == ['-A', hook]]
        owned = [rule for rule in snapshot if rule[:2] == ['-A', chain]]
        references = self.references(snapshot, chain)
        jump = expected['jump'] if expected else None
        evidence = {'entry': entry, 'hook': inputs, 'owned_chain': owned,
                    'references': references, 'expected': expected if expected else []}
        # 仅保留固定字段与摘要，规则中的地址、注释和其他链名不进入日志。
        return {'version': 1, 'reason': reason, 'family': version, 'hook': hook,
                'jump_position': inputs.index(jump) if jump in inputs else -1,
                'reference_count': len(references), 'chain_exists': ['-N', chain] in snapshot,
                'fingerprints': {key: hashlib.sha256(json.dumps(value, ensure_ascii=True,
                    separators=(',', ':'), sort_keys=True).encode('ascii')).hexdigest()
                    for key, value in evidence.items()}}

    def checked_snapshot(self, version):
        try:
            return self.snapshot(version)
        except Exception:
            self.last_diagnostic = self.diagnostic(version, 'query_failed')
            raise

    def valid_snapshot(self, version, snapshot):
        try:
            hook = self.hook(snapshot)
        except GuardError:
            self.last_diagnostic = self.diagnostic(version, 'entry_order_unknown', snapshot)
            return False
        chain, jump, rules = self.desired(version, hook)
        inputs = [r for r in snapshot if r[:2] == ['-A', hook]]
        existing = [r for r in snapshot if r[:2] == ['-A', chain]]
        references = self.references(snapshot, chain)
        if jump not in inputs:
            reason = 'jump_missing'
        elif inputs[0] != jump:
            reason = 'jump_reordered'
        elif references != [jump]:
            reason = 'reference_mismatch'
        elif existing != rules:
            reason = 'chain_mismatch'
        else:
            return True
        self.last_diagnostic = self.diagnostic(version, reason, snapshot, hook,
                                              {'jump': jump, 'rules': rules})
        return False

    def valid(self):
        self.last_diagnostic = None
        for version in (4, 6):
            _, snapshot = self.checked_snapshot(version)
            if not self.valid_snapshot(version, snapshot):
                return False
        return True

    def owned_state(self, version):
        binary, snapshot = self.checked_snapshot(version)
        policies = [rule for rule in snapshot if rule[:2] == ['-P', 'INPUT']]
        if len(policies) != 1 or policies[0] not in (['-P', 'INPUT', 'ACCEPT'], ['-P', 'INPUT', 'DROP']):
            self.last_diagnostic = self.diagnostic(version, 'entry_order_unknown', snapshot)
            raise GuardError('防火墙入口快照不完整，管理服务必须关闭。')
        try:
            hook = self.hook(snapshot)
        except GuardError:
            self.last_diagnostic = self.diagnostic(version, 'entry_order_unknown', snapshot)
            raise
        chain, jump, rules = self.desired(version, hook)
        references = self.references(snapshot, chain)
        allowed = [self.desired(version, origin)[1] for origin in ('INPUT', 'INPUT_FIREWALL', 'DEFAULT_INPUT')]
        if any(rule not in allowed for rule in references):
            self.last_diagnostic = self.diagnostic(version, 'reference_mismatch', snapshot, hook,
                                                  {'jump': jump, 'rules': rules})
            raise GuardError('专用保护链存在未知引用，管理服务必须关闭后检查。')
        return binary, snapshot, hook, chain, jump, rules, references

    def repair_plan(self, version):
        binary, _, hook, chain, jump, rules, references = self.owned_state(version)
        # --noflush 只重建此声明链；全部修改在一个 COMMIT 中生效，不逐条清空正在使用的链。
        lines = ['*filter', ':' + chain + ' - [0:0]']
        lines.extend(' '.join(rule) for rule in rules)
        lines.extend(' '.join(['-D'] + rule[1:]) for rule in references)
        lines.append(' '.join(['-I', hook, '1'] + jump[2:]))
        lines.append('COMMIT')
        payload = '\n'.join(lines) + '\n'
        if len(payload) > 64 * 1024:
            raise GuardError('专用保护规则过多，管理服务必须关闭后检查。')
        return [binary + '-restore', '--noflush', '--wait', '5'], payload

    def repair_live(self):
        self.last_diagnostic = None
        # 两族预检均通过后才写入；不接管未知入口、其他服务端口或陌生链引用。
        plans = [(version, self.repair_plan(version)) for version in (4, 6)]
        for version, (args, payload) in plans:
            self.restore(args, payload)
            _, snapshot = self.checked_snapshot(version)
            if not self.valid_snapshot(version, snapshot):
                raise GuardError('防火墙原子修复回读不一致，管理服务必须关闭。')
        if not self.valid():
            raise GuardError('防火墙原子修复最终校验失败，管理服务必须关闭。')
        return True

    def install(self):
        # 调用者须先停止容器；只重建本服务的链，构建完成前不开放监听。
        states = [self.owned_state(version) for version in (4, 6)]
        for binary, snapshot, hook, chain, jump, rules, references in states:
            if ['-N', chain] not in snapshot:
                self.run([binary, '-w', '5', '-N', chain])
            self.run([binary, '-w', '5', '-F', chain])
            for rule in rules:
                self.run([binary, '-w', '5'] + rule)
            for rule in references:
                self.run([binary, '-w', '5', '-D'] + rule[1:])
            self.run([binary, '-w', '5', '-I', hook, '1'] + jump[2:])
        if not self.valid():
            raise GuardError('防火墙回读不一致，管理服务保持关闭。')
