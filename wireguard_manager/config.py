import ipaddress
import os
import codecs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

from .utils import WGUtilsMixin
from .exceptions import ConfigSyntaxError


class WGConfigUtils():

    @staticmethod
    def _get_matching_config_line(config: str, key: str) -> str | None:
        for line in config.split('\n'):
            if key == line.split(' ', 1)[0]:
                value = line.split('= ', 1)[1].rstrip()
                return value
        return None

    @staticmethod
    def _get_matching_config_lines(config: str, key: str) -> list[str]:
        values = []
        for line in config.split('\n'):
            if key == line.split(' ', 1)[0]:
                value = line.split('= ', 1)[1].rstrip()
                values.append(value)
        return values

    @staticmethod
    def _encode_private_key(private_key: str) -> X25519PrivateKey:
        decoded_key = codecs.decode(private_key.encode('utf-8'), 'base64')
        private_key = X25519PrivateKey.from_private_bytes(decoded_key)
        return private_key

    @staticmethod
    def _decode_private_key(private_key: X25519PrivateKey):
        if private_key:
            bytes_ = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            return codecs.encode(bytes_, 'base64').decode('utf8').strip()
        return None

    @staticmethod
    def _stringify_config_line(key: str, value):
        if value:
            return f'{key} = {str(value)}\n'
        return ''

    @classmethod
    def _stringify_config_lines(cls, key: str, values: list):
        if values:
            return ''.join(cls._stringify_config_line(key, value) for value in values)
        return ''

    def __eq__(self, other):
        attrs = self.__dict__.keys()
        status = all(getattr(self, attr) == getattr(other, attr) for attr in attrs if attr != 'private_key')
        if self.private_key and other.private_key:
            status = status and self.private_key.public_key() == other.private_key.public_key()
        elif not self.private_key and not other.private_key:
            status = status and True
        else:
            status = False
        return status


class WGInterfaceConfig(WGConfigUtils):
    def __init__(self,
                 network: ipaddress.IPv4Network = None,
                 address: ipaddress.IPv4Address = None,
                 listen_port: int = None,
                 private_key: X25519PrivateKey = None,
                 dns: str = None,
                 table: int = None,
                 mtu: int = None,
                 pre_up: list[str] = None,
                 post_up: list[str] = None,
                 pre_down: list[str] = None,
                 post_down: list[str] = None):
        self.network = network
        self.address = address
        self.listen_port = listen_port
        self.private_key = private_key
        self.dns = dns
        self.table = table
        self.mtu = mtu
        self.pre_up = pre_up
        self.post_up = post_up
        self.pre_down = pre_down
        self.post_down = post_down

    @classmethod
    def load(cls, interface_section):
        network = ipaddress.ip_network(cls._get_matching_config_line(interface_section, 'Address'), strict=False)
        address = ipaddress.ip_address(cls._get_matching_config_line(interface_section, 'Address').split('/')[0])
        listen_port = int(cls._get_matching_config_line(interface_section, 'ListenPort'))
        private_key = cls._encode_private_key(cls._get_matching_config_line(interface_section, 'PrivateKey'))
        dns = cls._get_matching_config_line(interface_section, 'DNS')
        table_str = cls._get_matching_config_line(interface_section, 'Table')
        table = None
        if table_str:
            table = int(table_str)
        mtu_str = cls._get_matching_config_line(interface_section, 'MTU')
        mtu = None
        if mtu_str:
            mtu = int(mtu_str)
        pre_up = cls._get_matching_config_lines(interface_section, 'PreUp')
        post_up = cls._get_matching_config_lines(interface_section, 'PostUp')
        pre_down = cls._get_matching_config_lines(interface_section, 'PreDown')
        post_down = cls._get_matching_config_lines(interface_section, 'PostDown')
        return cls(network, address, listen_port, private_key, dns, table, mtu, pre_up, post_up, pre_down, post_down)

    def stringify(self):
        address_value = f'{self.address}/{self.network.prefixlen}'
        address_line = self._stringify_config_line('Address', address_value)
        listen_port_line = self._stringify_config_line('ListenPort', self.listen_port)
        private_key_line = self._stringify_config_line("PrivateKey", self._decode_private_key(self.private_key))
        dns_line = self._stringify_config_line('DNS', self.dns)
        table_line = self._stringify_config_line('Table', self.table)
        mtu_line = self._stringify_config_line('MTU', self.mtu)
        pre_up_lines = self._stringify_config_lines('PreUp', self.pre_up)
        post_up_lines = self._stringify_config_lines('PostUp', self.post_up)
        pre_down_lines = self._stringify_config_lines('PreDown', self.pre_down)
        post_down_lines = self._stringify_config_lines('PostDown', self.post_down)
        return f'[Interface]\n{address_line}{listen_port_line}{private_key_line}{dns_line}{table_line}{mtu_line}' \
               f'{pre_up_lines}{post_up_lines}{pre_down_lines}{post_down_lines}'


class WGPeerConfig(WGConfigUtils):
    def __init__(self,
                 allowed_ips_network: ipaddress.IPv4Network = None,
                 allowed_ips_address: ipaddress.IPv4Address = None,
                 name: str = None,
                 private_key: X25519PrivateKey = None,
                 persistent_keep_alive: int = None,
                 endpoint: str = None):
        self.allowed_ips_network = allowed_ips_network
        self.allowed_ips_address = allowed_ips_address
        self.name = name
        self.private_key = private_key
        self.persistent_keep_alive = persistent_keep_alive
        self.endpoint = endpoint

    @staticmethod
    def _decode_public_key(public_key: X25519PublicKey):
        if public_key:
            bytes_ = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return codecs.encode(bytes_, 'base64').decode('utf8').strip()
        return None

    @classmethod
    def load(cls, peer_section: str):
        allowed_ips_line = cls._get_matching_config_line(peer_section, 'AllowedIPs')
        allowed_ips_network = None
        allowed_ips_address = None
        if allowed_ips_line:
            allowed_ips_network = ipaddress.ip_network(allowed_ips_line, strict=False)
            allowed_ips_address = ipaddress.ip_address(allowed_ips_line.split('/')[0])
        name = cls._get_matching_config_line(peer_section, '#Name')
        private_key = cls._encode_private_key(cls._get_matching_config_line(peer_section, '#PrivateKey'))
        persistent_keep_alive = int(cls._get_matching_config_line(peer_section, 'PersistentKeepalive'))
        endpoint = cls._get_matching_config_line(peer_section, 'Endpoint')
        return cls(allowed_ips_network, allowed_ips_address, name, private_key, persistent_keep_alive, endpoint)

    def stringify(self):
        allowed_ips_value = f'{self.allowed_ips_address}/{self.allowed_ips_network.prefixlen}'
        allowed_ips_line = self._stringify_config_line('AllowedIPs', allowed_ips_value)
        name_line = self._stringify_config_line('#Name', self.name)
        private_key_line = self._stringify_config_line('#PrivateKey', self._decode_private_key(self.private_key))
        public_key_line = self._stringify_config_line("PublicKey",
                                                      self._decode_public_key(self.private_key.public_key()))
        persistent_keep_alive_line = self._stringify_config_line("PersistentKeepalive", self.persistent_keep_alive)
        endpoint = self._stringify_config_line("Endpoint", self.endpoint)
        return f'[Peer]\n{name_line}{allowed_ips_line}{public_key_line}{persistent_keep_alive_line}{endpoint}{private_key_line}'


class WGConfig(WGUtilsMixin):
    interface_appropriate_keys = [
        "Address", "ListenPort", "PrivateKey", "DNS", "Table", "MTU",
        "PreUp", "PostUp", "PreDown", "PostDown"
    ]
    peer_appropriate_keys = [
        "Endpoint", "AllowedIPs", "PublicKey", "PersistentKeepalive"
    ]

    def __init__(self,
                 path: os.PathLike | None = None,
                 interface_config: WGInterfaceConfig = None,
                 peer_configs: list[WGPeerConfig] = None):
        self.path = path
        if path:
            self.name = os.path.basename(path).split('.')[0]
        else:
            self.name = None
        self.interface_config = interface_config
        self.peer_configs = peer_configs

    @classmethod
    def load(cls, path: os.PathLike):
        if not os.path.exists(path):
            raise FileNotFoundError("Configuration file does not found")
        with open(path, 'r') as file:
            config_raw = file.read()
        cls._check_syntax(config_raw)

        interface_section = cls._extract_interface_section(config_raw)
        interface_config = WGInterfaceConfig.load(interface_section)
        peer_sections = cls._extract_peers_section(config_raw)
        peer_configs = []
        if peer_sections:
            for peer_section in peer_sections:
                peer_configs.append(WGPeerConfig.load(peer_section))
        return cls(path, interface_config, peer_configs)

    @classmethod
    def _extract_interface_section(cls, config: str) -> str:
        if '[Interface]\n' not in config:
            raise ConfigSyntaxError(f"'[Interface]' section is not declared]")
        interface_section = config.split('[Interface]\n', 1)[1]
        interface_section = interface_section.split('[Peer]\n', 1)[0]
        return interface_section

    @classmethod
    def _extract_peers_section(cls, config: str) -> list[str] | None:
        if '[Peer]\n' not in config:
            return None
        peers_sections = config.split('[Peer]\n', )[1:]
        return peers_sections

    @classmethod
    def _check_syntax(cls, config: str):
        config_without_comments = '\n'.join(filter(lambda x: '#' not in x, config.split('\n')))
        interface_section = cls._extract_interface_section(config_without_comments)
        for number, line in enumerate(interface_section.split('\n'),1):
            if not line.isspace() and len(line) != 0:
                key = line.split(' ', 1)[0]
                if key not in cls.interface_appropriate_keys:
                    raise ConfigSyntaxError(f"Inappropriate interface section key '{key}' in line {number}")

        peer_sections = cls._extract_peers_section(config_without_comments)
        if peer_sections:
            for peer_section in peer_sections:
                for line in peer_section.split('\n'):
                    if not line.isspace():
                        key = line.split(' ', 1)[0]
                        if key not in cls.peer_appropriate_keys:
                            raise ConfigSyntaxError(f"Inappropriate peer section key '{key}'")

    def stringify(self) -> str:
        interface_lines = self.interface_config.stringify()
        peers_lines = ''
        if self.peer_configs:
            peers_lines = '\n'.join(peer_config.stringify() for peer_config in self.peer_configs)
        return f'{interface_lines}\n\n{peers_lines}'

    def save(self):
        config_text = self.stringify()
        with open(self.path, 'w') as file:
            file.write(config_text)

    def delete(self):
        os.remove(self.path)
