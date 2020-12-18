from netaddr import IPAddress, AddrFormatError


class RuleSyntaxChecker:
	
	def _check_rule(self, rule):
		# check whether the given rule has a valid syntax.
		ip_src = rule['ip_src']
		ip_dst = rule['ip_dst']
		tp_proto = rule['tp_proto']
		port_src = rule['port_src']
		port_dst = rule['port_dst']
		action = rule['action']
		errors = []
		
		ip_src_result = self._check_ip(ip_src)
		ip_dst_result = self._check_ip(ip_dst)
		if not ip_src_result:
			errors.append("Invalid source IP address: " + ip_src)
		if not ip_dst_result:
			errors.append("Invalid destination IP address: " + ip_dst)
		if ip_src_result and ip_dst_result:
			if not self._check_ip_versions(ip_src, ip_dst):
				errors.append("Unsupported rule: both IP addresses must be of the same version.")
		if not self._check_transport_protocol(tp_proto):
			errors.append("Invalid transport protocol (layer 4): " + tp_proto)
		if not self._check_port(port_src):
			errors.append("Invalid source port: " + port_src)
		if not self._check_port(port_dst):
			errors.append("Invalid destination port: " + port_dst)
		if not self._check_transport_valid(tp_proto, port_src, port_dst):
			errors.append("Unsupported rule: transport protocol: " + tp_proto + " source port: " + port_src + " destination port: " + port_dst)
		if not self._check_action(action):
		 	errors.append("Unsupported action: {0}".format(action))
		return errors
		
	def _check_ip(self, address):
		# check whether a valid IP (v4 or v6) address has been specified.
		try:
			addr = IPAddress(address)
			return True
		except AddrFormatError:
			if address == '*':
				return True
			return False
			
	def _check_ip_versions(self, ip_src, ip_dst):
		# check that the source and destination IP addresses are of
		if ip_src == "*" and ip_dst == "*":
			return False
		if ip_src == "*" or ip_dst == "*":
			return True
		return IPAddress(ip_src).version == IPAddress(ip_dst).version
		
	def _check_transport_protocol(self, protocol):
		# check that the specified transport layer (layer 4) protocol is either "*", TCP, or UDP
		return (protocol == "tcp" or protocol == "udp" or protocol == "*")
		
	def _check_port(self, port):
		# a port is valid if it is either "*" or between 0 and 65535 inclusive.
		try:
			int(port)
			if int(port) < 0 or int(port) > 65535:
				return False
			return True
		except ValueError:
			if port == "*":
				return True
			return False
			
	def _check_transport_valid(self, tp_proto, port_src, port_dst):
		# a rule is not valid if the tp_proto is "*" and port numbers are specified.
		return not(tp_proto == "*" and (port_src != "*" or port_dst != "*"))
		
	def _check_action(self, action):
		# the only supported action for firewall rules, which are based on black-listing, is drop.
		return action == "drop"
		
		
		
