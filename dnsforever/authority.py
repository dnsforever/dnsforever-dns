from twisted.names.authority import BindAuthority


class DnsforeverAuthority(BindAuthority):
    def __init__(self, serverAddr):
        self.serverAddr = serverAddr
        self.records = {}

    def update(self):
        self.addRecord('dnsforever.kr', 300, 'A', '@', 'IN', ['1.2.3.4'])