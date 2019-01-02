import collections
class Firewall:
	INBOUND = "inbound"
	TCP = "tcp"

	def __init__(self, path):
		self.inbound_tcp_dict = collections.defaultdict(list)
		self.outbound_tcp_dict = collections.defaultdict(list)
		self.inbound_udp_dict = collections.defaultdict(list)
		self.outbound_udp_dict = collections.defaultdict(list)
		self._parse_input(path)
		self.sorted_inbound_tcp_dict = collections.OrderedDict(sorted(self.inbound_tcp_dict.items(), key=lambda k: k[0]))
		self.sorted_outbound_tcp_dict = collections.OrderedDict(sorted(self.outbound_tcp_dict.items(), key=lambda k: k[0]))
		self.sorted_inbound_udp_dict = collections.OrderedDict(sorted(self.inbound_udp_dict.items(), key=lambda k: k[0]))
		self.sorted_outbound_udp_dict = collections.OrderedDict(sorted(self.outbound_udp_dict.items(), key=lambda k: k[0]))

	def _parse_input(self, path):
		file = open(path, "r")
		for line in file:
			line = line.replace("\n", "")
			info = line.split(",")
			is_inbound = info[0] == self.INBOUND
			is_tcp = info[1] == self.TCP
			self._add_protocol_dict(is_inbound, is_tcp, info)

	def _add_protocol_dict(self, is_inbound, is_tcp, info):
		ports = info[2].replace("--", "-").split("-")
		port_range = None
		if len(ports) == 1:
			port_range = (int(ports[0]), int(ports[0]))
		else:
			port_range = (int(ports[0]), int(ports[1]))

		ips = info[3].split("-")
		ip_range = None
		if len(ips) == 2:
			ip_range = [ips[0], ips[1]]
		else:
			ip_range = ips

		if is_inbound and is_tcp:
			self.inbound_tcp_dict[port_range] += ip_range
		elif is_inbound and not is_tcp:
			self.inbound_udp_dict[port_range] += ip_range
		elif not is_inbound and is_tcp:
			self.outbound_tcp_dict[port_range] += ip_range
		else:
			self.outbound_udp_dict[port_range] += ip_range

	def accept_packet(self, direction, protocol, port, ip_address):
		is_inbound = direction == self.INBOUND
		is_tcp = protocol == self.TCP

		if is_inbound and is_tcp:
			return self._check_ip(self.sorted_inbound_tcp_dict, port, ip_address)
		elif is_inbound and not is_tcp:
			return self._check_ip(self.sorted_inbound_udp_dict, port, ip_address)
		elif not is_inbound and is_tcp:
			return self._check_ip(self.sorted_outbound_tcp_dict, port, ip_address)
		else:
			return self._check_ip(self.sorted_outbound_udp_dict, port, ip_address)

		raise Exception("Invalid Input")


	def _check_ip(self, protocol_dict, port, ip_address):
		ip_int = self._ip_to_int(ip_address)
		for port_range, ip_range in protocol_dict.items():
			if port_range[0] <= port <= port_range[1]:
				if len(ip_range) == 2:
					low_ip = self._ip_to_int(ip_range[0])
					high_ip = self._ip_to_int(ip_range[1])
					if low_ip <= ip_int <= high_ip:
						return True
				else:
					return ip_address == ip_range[0]
		return False

	def _ip_to_int(self, ip_address):
		o = map(int, ip_address.split("."))
		res = (o[0] << 24) + (o[1] << 16) + (o[2] << 8) + o[3]
		return res


fw = Firewall("input.csv")
print fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")
print fw.accept_packet("inbound", "udp", 53, "192.168.2.1")
print fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")
print fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")
print fw.accept_packet("inbound", "udp", 24, "52.12.48.92")

