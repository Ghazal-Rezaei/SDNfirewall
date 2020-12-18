from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as ofp13_parser
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import hub
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import ether_types

from switch import EnhancedSwitch13
from ruleSyntaxChecker import RuleSyntaxChecker

from webob import Response
from netaddr import IPAddress, AddrFormatError
from operator import attrgetter
import datetime
import json
import logging


class AdvancedFirewall(EnhancedSwitch13):

	_CONTEXTS = {'wsgi': WSGIApplication}

	# initializing default values
	_RULE_TCP = "tcp"
	_RULE_UDP = "udp"
	_RULE_WILDCARD = "*"

	# constants related to monitoring function
	# a constant used in the anomaly detection formula
	# which will be defined according to the requirements of the network
	CONSTANT = 53
	# record keeping database template
	MATCH_STATS = {'predictedTraffic':0,'currentTraffic':0,'restricted':False}
	
	def __init__(self, *args, **kwargs):
		super(AdvancedFirewall, self).__init__(*args, **kwargs)
		
		# registering the class with WSGI
		wsgi = kwargs['wsgi']
		wsgi.register(FirewallController, {'firewall_api_app': self})
		
		# initialize the policy-rule table
		self._pol_to_rule = {}
		
		# make a RuleSyntaxChecker instance	
		self.RSC = RuleSyntaxChecker()
		logging.info('Starting the firewall...')
		
		# a dict for keeping traffic matching each flow for analysis
		self.matches = {}
		
		# creating a thread to periodically issue a request to the OpenFlow switches to acquire statistical information.
		self.monitor_thread = hub.spawn(self._monitor)
		logging.info('Start monitoring...')

	# filtering and management related functionalities--------------------------------------------------------------------------		
	def pol_dict_form(self,policy_name):
		return {'name':policy_name, 'sensitivity':self._pol_to_rule[policy_name][0]}
	
	def policy_create(self, policy):
		# create a policy domain.
		# policy: The policy domain.
		# return: True if successful, False otherwise.
		
		policy_name = policy['name']
		if self.policy_exists(policy_name):
			logging.warning("Cannot create policy %s as it already exists.", policy_name)
			return False
		
		policy_sensitivity = float(policy['sensitivity'])	
		self._pol_to_rule[policy_name] = (policy_sensitivity,[])
		logging.info("Created policy: %s", policy_name)
		return True
		
	def policy_remove(self, policy):
		# remove a policy domain.
		# and propagate the results making sure that switches in the respective policy domain do not have the mentioned rules any longer.
		# Then revoke the policy from the mentioned switches.
		# policy: The policy domain.
		# return: True if successful, False otherwise.
		
		if not self.policy_exists(policy):
			logging.warning("Cannot remove policy %s as it does not exist.", policy_name)
			return False
		
		self.policy_make_empty(policy)
		
		pol = self.pol_dict_form(policy)
		for switch in self._list_pol_switches(pol):
			self._switch_del_pol(pol,switch)
			
		del(self._pol_to_rule[policy])
		logging.info("Removed policy: %s", policy)
		return True
	
	def policy_exists(self, policy):
		return (policy in self.list_pols())
		
	def list_pols(self):
		return list(self._pol_to_rule.keys())
		
	def policy_make_empty(self, policy):
		# remove every rule belonging to a given policy
		
		for rule in self.list_pol_rules(policy):
			result = self.policy_del_rule(rule,policy)
		
	def policy_add_rule(self, rule, policy):
		# add a given rule to a desired policy
		
		# check whether a valid policy is required
		if not self.policy_exists(policy):
			logging.error("Cannot assign the rule to the policy %s as it does not exist.", policy)
			return False
		
		match = self._create_match(rule)
		logging.debug(match)
		self._pol_to_rule[policy][1].append(rule)
		pol = self.pol_dict_form(policy)
		for switchID in self._list_pol_switches(pol):
			# switchID is the same as datapathID in EnhancedSwitch13 class
			actions = [] # no action simply indicates dropping
			if rule['action'] == 'drop':
				# installing the block rules with a higher priority (with priority=2) than normal flows (with priority=1)
				# so that first unauthorized traffic is filtered 
				# and the remaning traffic is considered benign and forwarded
				# it might be noted that since normal flows receive a lower priority, we face no problem blocking them later
				self.add_flow(self.datapaths[switchID], 2, match, actions)
				logging.debug("Applied the given rule to related switch with ID = " + str(switchID))
		return True
		
	def policy_del_rule(self, rule, policy):
		# remove a given rule from a desired policy
		
		# check whether a valid policy is required
		if not self.policy_exists(policy):
			logging.error("Cannot revoke the rule from the policy %s as it does not exist.", policy)
			return False
			
		# check whether the policy has the respective rule
		if not self.policy_has_rule(rule, policy):
			logging.error("Cannot revoke the rule from the policy %s as it does not have it.", policy)
			return False
		match = self._create_match(rule)
		actions = []
		self._pol_to_rule[policy][1].remove(rule)
		pol = self.pol_dict_form(policy)
		for switchID in self._list_pol_switches(pol):
			# switchID is the same as datapathID in EnhancedSwitch13 class
			self.del_flow(self.datapaths[switchID], 2, match)
			logging.debug("Revoked the given rule from the related switch with ID = " + str(switchID))
		return True
			
	def list_pol_rules(self, policy):
		if self.policy_exists(policy):
			return self._pol_to_rule[policy][1]
		else:
			logging.error("Cannot list the rules of policy %s as it does not exist.", policy)
			empty_list = []
			return empty_list
		
	def policy_has_rule(self, rule, policy):
		return (rule in self.list_pol_rules(policy))
		
	def pol_assign_switch(self, policy, switchID):
		# assing a given policy to a desired switch
		
		if not self.policy_exists(policy):
			logging.error("Cannot assign the given policy to the switch since the policy domain does not exist.")
			return False
			
		pol = self.pol_dict_form(policy)	
		if not self._switch_add_pol(pol, switchID):
			return False
		
		actions = [] # no action simply indicates dropping
		for rule in self.list_pol_rules(policy):
			match = self._create_match(rule)
			if rule['action'] == 'drop':
				self.add_flow(self.datapaths[switchID], 2, match, actions)
			logging.debug("Applied the rule " + str(rule) +" to related switch with ID = " + str(switchID))
		return True
		
	def pol_revoke_switch(self, policy, switchID):
		# assing a given policy to a desired switch
		
		if not self.policy_exists(policy):
			logging.error("Cannot revoke the given policy from the switch since the policy domain does not exist.")
			return False
		
		pol = self.pol_dict_form(policy)	
		if not self._switch_del_pol(pol, switchID):
			return False
		
		for rule in self.list_pol_rules(policy):
			match = self._create_match(rule)
			actions = []
			self.del_flow(self.datapaths[switchID], 2, match)
			logging.debug("Revoked the rule " + str(rule) +" from related switch with ID = " + str(switchID))
		return True
			
	def rule_create(self, rule):
		# first check if the rule has a valid syntax.
		errors = self.RSC._check_rule(rule)
		
		if len(errors):
			logging.error("Cannot create the rule as its syntax is not valid.")
			for e in errors:
				logging.error(e)
			return False
		
		else:
			if not self._rule_exists(rule):
				if self.policy_add_rule(rule,rule['policy']):
					return True
				return False
			else:
				logging.error("Cannot create the rule as it already exists.")
				return False
		
	def rule_remove(self, rule):
		# first check if the rule has a valid syntax.
		errors = self.RSC._check_rule(rule)
		
		if len(errors):
			logging.error("Cannot remove the rule as its syntax is not valid.")
			for e in errors:
				logging.error(e)
			return False
		
		else:
			if self.policy_del_rule(rule,rule['policy']):
				return True
			return False
			
	def _rule_exists(self, rule):
		# check whether a given rule already exists
		for pol in self.list_pols():
			if self.policy_has_rule(rule, pol):
				return True
		return False
		
	def _create_match(self, rule):
		# create an OFPMatch instance based on the contents of a given rule
		logging.debug('Creating the match for the given rule...')
		
		ip_version = self._return_ip_version(rule['ip_src'], rule['ip_dst'])
		
		# match IP layer (layer 3)
		if ip_version == 4:
			# match IPv4
			if rule['ip_src'] != '*' and rule['ip_dst'] != '*':
				# both source and destination IP addresses are specified
				
				# match layer 4
				if rule['tp_proto'] == '*':
					match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), ipv4_dst = IPAddress(rule['ip_dst']), eth_type=ether_types.ETH_TYPE_IP)
					return match
				elif rule['tp_proto'] == 'tcp':
					# match tcp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), ipv4_dst = IPAddress(rule['ip_dst']), tcp_src = int(rule['port_src']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), ipv4_dst = IPAddress(rule['ip_dst']), tcp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), ipv4_dst = IPAddress(rule['ip_dst']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
						
				elif rule['tp_proto'] == 'udp':
					# match udp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), ipv4_dst = IPAddress(rule['ip_dst']), udp_src = int(rule['port_src']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), ipv4_dst = IPAddress(rule['ip_dst']), udp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), ipv4_dst = IPAddress(rule['ip_dst']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
						
			elif rule['ip_dst'] == '*':
				# Only source IP address is specified
				
				# match layer 4
				if rule['tp_proto'] == '*':
					match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), eth_type=ether_types.ETH_TYPE_IP)
					return match
				elif rule['tp_proto'] == 'tcp':
					# match tcp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), tcp_src = int(rule['port_src']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), tcp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
						
				elif rule['tp_proto'] == 'udp':
					# match udp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), udp_src = int(rule['port_src']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), udp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv4_src = IPAddress(rule['ip_src']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
				
			else:
				# Only destination IP address is specified
				
				# match layer 4
				if rule['tp_proto'] == '*':
					match = ofp13_parser.OFPMatch(ipv4_dst = IPAddress(rule['ip_dst']), eth_type=ether_types.ETH_TYPE_IP)
					return match
				elif rule['tp_proto'] == 'tcp':
					# match tcp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv4_dst = IPAddress(rule['ip_dst']), tcp_src = int(rule['port_src']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv4_dst = IPAddress(rule['ip_dst']), tcp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv4_dst = IPAddress(rule['ip_dst']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
						
				elif rule['tp_proto'] == 'udp':
					# match udp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv4_dst = IPAddress(rule['ip_dst']), udp_src = int(rule['port_src']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv4_dst = IPAddress(rule['ip_dst']), udp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv4_dst = IPAddress(rule['ip_dst']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
						
		if ip_version == 6:
			# match IPv6
			if rule['ip_src'] != '*' and rule['ip_dst'] != '*':
				# both source and destination IP addresses are specified
				
				# match layer 4
				if rule['tp_proto'] == '*':
					match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), ipv6_dst = IPAddress(rule['ip_dst']), eth_type=ether_types.ETH_TYPE_IP)
					return match
				elif rule['tp_proto'] == 'tcp':
					# match tcp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), ipv6_dst = IPAddress(rule['ip_dst']), tcp_src = int(rule['port_src']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), ipv6_dst = IPAddress(rule['ip_dst']), tcp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), ipv6_dst = IPAddress(rule['ip_dst']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
						
				elif rule['tp_proto'] == 'udp':
					# match udp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), ipv6_dst = IPAddress(rule['ip_dst']), udp_src = int(rule['port_src']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), ipv6_dst = IPAddress(rule['ip_dst']), udp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), ipv6_dst = IPAddress(rule['ip_dst']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
						
			elif rule['ip_dst'] == '*':
				# Only source IP address is specified
				
				# match layer 4
				if rule['tp_proto'] == '*':
					match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), eth_type=ether_types.ETH_TYPE_IP)
					return match
				elif rule['tp_proto'] == 'tcp':
					# match tcp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), tcp_src = int(rule['port_src']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), tcp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
						
				elif rule['tp_proto'] == 'udp':
					# match udp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), udp_src = int(rule['port_src']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), udp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv6_src = IPAddress(rule['ip_src']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
				
			else:
				# Only destination IP address is specified
				
				# match layer 4
				if rule['tp_proto'] == '*':
					match = ofp13_parser.OFPMatch(ipv6_dst = IPAddress(rule['ip_dst']), eth_type=ether_types.ETH_TYPE_IP)
					return match
				elif rule['tp_proto'] == 'tcp':
					# match tcp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv6_dst = IPAddress(rule['ip_dst']), tcp_src = int(rule['port_src']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv6_dst = IPAddress(rule['ip_dst']), tcp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv6_dst = IPAddress(rule['ip_dst']), tcp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
						
				elif rule['tp_proto'] == 'udp':
					# match udp
					if rule['port_src'] != '*' and rule['port_dst'] != '*':
						# both source and destination ports are specified
						match = ofp13_parser.OFPMatch(ipv6_dst = IPAddress(rule['ip_dst']), udp_src = int(rule['port_src']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					elif rule['port_dst'] != '*':
						# only source port is specified
						match = ofp13_parser.OFPMatch(ipv6_dst = IPAddress(rule['ip_dst']), udp_src = int(rule['port_src']), eth_type=ether_types.ETH_TYPE_IP)
						return match
					else:
						# only destination port is specified
						match = ofp13_parser.OFPMatch(ipv6_dst = IPAddress(rule['ip_dst']), udp_dst = int(rule['port_dst']), eth_type=ether_types.ETH_TYPE_IP)
						return match
				
		
	def _return_ip_version(self, ip_src, ip_dst):
		# return the IP version being used given the source and destination addresses.
		if self._RULE_WILDCARD not in ip_src:
			return IPAddress(ip_src).version
		else:
			return IPAddress(ip_dst).version
	
	# monitoring related functionalities----------------------------------------------------------------------------------------		
	@set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
	def _state_change_handler(self, ev):
		# handle state changes in the network
	    	
		datapath = ev.datapath
		if ev.state == MAIN_DISPATCHER:
			if datapath.id not in self.datapaths:
				logging.debug('Register datapath: %016x', datapath.id)
				self.datapaths[datapath.id] = datapath
		elif ev.state == DEAD_DISPATCHER:
			if datapath.id in self.datapaths:
				logging.debug('Unregister datapath: %016x', datapath.id)
				del self.datapaths[datapath.id]

	def _monitor(self):
		# periodically monitor the traffic load in the network
		
		while True:
			for dp in self.datapaths.values():
				self._request_stats(dp)
			hub.sleep(5)

	def _request_stats(self, datapath):
		# request statistics saved in a given switch
	
		logging.debug('Send stats request: %016x', datapath.id)
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		# request flow statistics
		req = parser.OFPFlowStatsRequest(datapath)
		datapath.send_msg(req)

	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def _flow_stats_reply_handler(self, ev):
		# an event handler that receives the statistical information of each flow entry
		
		body = ev.msg.body
		for stat in body:
			# if the flow is a regular one, not a firewall rule, check its stats
			if stat.priority == 1:
                             self._anomaly_detection(ev.msg.datapath.id, stat.match, stat.byte_count)
	                             
	def _anomaly_detection(self, switchID ,match, byte_count):
		# check whether the load of the traffic matching the given flow exceeds some threshold
		
		# generate a key to facilitate ordering and searching the data available at matches table
		key = self._generate_key(switchID ,match)
		
		# deriving the desired sensitivity of the formula for the given switch
		gain = self._get_switch_gain(switchID)
		# if the sensitivity of the formula for the given switch is not defined yet
		if gain == 1:
			return
			
		if key in self.matches:
			self.matches[key]['currentTraffic'] = self.matches[key]['predictedTraffic'] = byte_count
		
		# if no prior account of the flow is available add it to the database
		else:
			logging.info('Pushing a new record in the table with key = '+key)
			self.matches[key] = self.MATCH_STATS.copy()
			self.matches[key]['predictedTraffic'] = 0
			self.matches[key]['currentTraffic'] = byte_count
		# using exponential weighted moving average formula to evaluate the current traffic against the expected one
		expected = gain*self.matches[key]['predictedTraffic'] + (1-gain)*self.matches[key]['currentTraffic'] + self.CONSTANT
		self.matches[key]['predictedTraffic'] = expected
		logging.debug(key)
		logging.debug('Expected volume of traffic is ' + str(expected))
		logging.debug('Real volume of traffic is ' + str(self.matches[key]['currentTraffic']))
		
		if expected < self.matches[key]['currentTraffic']:
		
			# in case traffic is not already restricted
			if not self.matches[key]['restricted']:
				# if the current traffic load exceeds the expected load, it is probably abnormal
				# hence, it should be filtered for a while until it is returned to the normal state
				
				actions = [] # no action simply indicates dropping
				self.add_flow(self.datapaths[switchID], 3, match, actions) # a temporary flow to drop overloaded traffic
				self.matches[key]['restricted'] = True
				logging.debug("Restricted the suspicious flow in the related switch with ID = %016x", switchID)
			
		# in case traffic has already been restricted for a timespan long enough to return to normal state
		elif self.matches[key]['restricted']:
				self.del_flow(self.datapaths[switchID], 3, match)
				self.matches[key]['restricted'] = False
				logging.debug("Unrestricting the once suspicious flow in the related switch with ID = %016x", switchID)
				                             
	def _generate_key(self, switchID ,match):
		# generating a unique key for each flow in every switch's flow table
		in_port = str(match.get('in_port',0))
		eth_src = str(match.get('eth_src',0))
		eth_dst = str(match.get('eth_dst',0))
		tcp_src = str(match.get('tcp_src',0))
		tcp_dst = str(match.get('tcp_dst',0))
		udp_src = str(match.get('udp_src',0))
		udp_dst = str(match.get('udp_dst',0))
		return str(switchID)+in_port+eth_src+eth_dst+tcp_src+tcp_dst+udp_src+udp_dst
					
	
class FirewallController(ControllerBase):
	# a class serving as the user interface to manipulate the network state through the firewall.
	# the mentioned goal can be achieved by adding/deleting/listing rules, policies, etc on the fly.

	# URLs
	_URL = '/firewall'
	_URL_RULE = _URL + '/rule'
	_URL_POLICY_RULE = _URL_RULE + '/policy_name/{policy}'
	_URL_POLICY = _URL + '/policy'
	_URL_SWITCH = _URL + '/switch'
	_URL_POLICY_SWITCH = _URL_SWITCH + '/policy_name/{policy}'
	_URL_SINGLE_SWITCH = _URL_SWITCH + '/id/{dpid}'
	
	# outgoing message templates
	_MSG_CRITICAL = {"critical": ""}
	_MSG_ERROR = {"error": ""}
	_MSG_INFO = {"info": ""}
	_MSG_WARNING = {"warning": ""}

	def __init__(self, req, link, data, **config):
		super(FirewallController, self).__init__(req, link, data, **config)
		self.firewall = data['firewall_api_app']
		
	# rule endpoints -------------------------------------------------------------------------------------------------------------------------
	@route("WSGI", _URL_POLICY_RULE, methods=["GET"])	
	def list_pol_rules(self, req, **kwargs):
		# endpoint for listing all the rules relating to a given policy
		
		rule_list = self.firewall.list_pol_rules(kwargs['policy'])
		body = json.dumps(rule_list)
		return Response(content_type='application/json', charset='utf-8', body=body)
	
	@route("WSGI", _URL_RULE, methods=["POST"])	
	def rule_create(self, req, **kwargs):
		# endpoint for creating rules
		
		try:
			rule = json.loads(req.body.decode("utf-8"))
			if not self.firewall.rule_create(rule):
				raise KeyError
		except (ValueError,KeyError):
			error = self._MSG_ERROR.copy()
			error["error"] = "Invalid rule creation JSON passed."
			return Response(status=400, body=json.dumps(error), charset="UTF-8")
		
		info = self._MSG_INFO.copy()
		info["info"] = "Rule was created successfully."
		return Response(status=200, body=json.dumps(info), charset="UTF-8")
	
	@route("WSGI", _URL_RULE, methods=["DELETE"])	
	def rule_remove(self, req, **kwargs):
		# endpoint for removing rules
		
		try:
			rule = json.loads(req.body.decode("utf-8"))
			if not self.firewall.rule_remove(rule):
				raise KeyError
		except (ValueError,KeyError):
			error = self._MSG_ERROR.copy()
			error["error"] = "Invalid rule removal JSON passed."
			return Response(status=400, body=json.dumps(error), charset="UTF-8")
		
		info = self._MSG_INFO.copy()
		info["info"] = "Rule was removed successfully."
		return Response(status=200, body=json.dumps(info), charset="UTF-8")
			
	# policy endpoints -----------------------------------------------------------------------------------------------------------------------
	@route("WSGI", _URL_POLICY, methods=["GET"])	
	def list_pols(self, req, **kwargs):
		# endpoint for listing all policies
		
		policy_list = self.firewall.list_pols()
		body = json.dumps(policy_list)
		return Response(content_type='application/json', charset='utf-8', body=body)
	
	@route("WSGI", _URL_POLICY, methods=["POST"])	
	def policy_create(self, req, **kwargs):
		# endpoint for creating plicies
		
		try:
			policy = json.loads(req.body.decode("utf-8"))
			if not self.firewall.policy_create(policy):
				raise KeyError
		except (ValueError,KeyError):
			error = self._MSG_ERROR.copy()
			error["error"] = "Invalid policy domain creation JSON passed."
			return Response(status=400, body=json.dumps(error), charset="UTF-8")
		
		info = self._MSG_INFO.copy()
		info["info"] = "Policy domain was created successfully."
		return Response(status=200, body=json.dumps(info), charset="UTF-8")
	
	@route("WSGI", _URL_POLICY, methods=["DELETE"])	
	def policy_remove(self, req, **kwargs):
		# endpoint for removing policies
		
		try:
			policy = json.loads(req.body.decode("utf-8"))
			if not self.firewall.policy_remove(policy['policy']):
				raise KeyError
		except (ValueError,KeyError):
			error = self._MSG_ERROR.copy()
			error["error"] = "Invalid policy domain removal JSON passed."
			return Response(status=400, body=json.dumps(error), charset="UTF-8")
		
		info = self._MSG_INFO.copy()
		info["info"] = "Policy domain was removed successfully."
		return Response(status=200, body=json.dumps(info), charset="UTF-8")

	# switch endpoints -----------------------------------------------------------------------------------------------------------------------
	@route("WSGI", _URL_POLICY_SWITCH, methods=["GET"])	
	def list_pol_switches(self, req, **kwargs):
		# endpoint for listing all the switches relating to a given policy
		
		switch_list = self.firewall._list_pol_switches(self.firewall.pol_dict_form(kwargs['policy']))
		body = json.dumps(switch_list)
		return Response(content_type='application/json', charset="UTF-8",  body=body)	
		
	@route("WSGI", _URL_SINGLE_SWITCH, methods=["GET"], requirements={'dpid': dpid_lib.DPID_PATTERN})
	def list_switch_pols(self, req, **kwargs):
		# endpoint for listing all the policies assigned to a single switch
		
		pol_list = self.firewall._list_switch_pols(dpid_lib.str_to_dpid(kwargs['dpid']))
		body = json.dumps(pol_list)
		return Response(content_type='application/json', charset="UTF-8", body=body)	
	
	@route("WSGI", _URL_SINGLE_SWITCH, methods=["POST"], requirements={'dpid': dpid_lib.DPID_PATTERN})
	def pol_assign_switch(self, req, **kwargs):
		# endpoint for assigning a policy to a single switch
	
		switchID = dpid_lib.str_to_dpid(kwargs['dpid'])
		try:
			policy = json.loads(req.body.decode("utf-8"))
			if not self.firewall.pol_assign_switch(policy['policy'],switchID):
				raise KeyError
		except (ValueError,KeyError):
			error = self._MSG_ERROR.copy()
			error["error"] = "Invalid switch identifier or policy domain assignment JSON passed."
			return Response(status=400, body=json.dumps(error), charset="UTF-8")
		
		info = self._MSG_INFO.copy()
		info["info"] = "Policy domain was successfully assigned to the switch"
		return Response(status=200, body=json.dumps(info), charset="UTF-8")
	
	@route("WSGI", _URL_SINGLE_SWITCH, methods=["DELETE"], requirements={'dpid': dpid_lib.DPID_PATTERN})
	def pol_revoke_switch(self, req, **kwargs):
		# endpoint for revoking a policy from a single switch
	
		switchID = dpid_lib.str_to_dpid(kwargs['dpid'])
		try:
			policy = json.loads(req.body.decode("utf-8"))
			if not self.firewall.pol_revoke_switch(policy['policy'],switchID):
				raise KeyError
		except (ValueError,KeyError):
			error = self._MSG_ERROR.copy()
			error["error"] = "Invalid switch identifier or policy domain revoking JSON passed."
			return Response(status=400, body=json.dumps(error), charset="UTF-8")
		
		info = self._MSG_INFO.copy()
		info["info"] = "Policy domain was successfully revoked from the switch"
		return Response(status=200, body=json.dumps(info), charset="UTF-8")
	
		
		

