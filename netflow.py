# -*- coding: utf-8 -*-
import SocketServer
import time
import sys
import requests
import json

from struct import unpack
from sched import scheduler
from socket import inet_ntop, AF_INET, AF_INET6
from threading import Thread
from urllib2 import URLError
from Queue import Queue

netflow_queue = Queue()
netflow_normalized_queue = Queue()

class TransferThread(Thread):
	def __init__(self, logger, args, options):
		Thread.__init__(self)
		self.logger = logger
		self.args = args
		self.options = options
		self.tasks = scheduler(time.time, time.sleep)
		self.stop_flag = False
	
	def run(self):
		self.tasks.enter(5, 1, self.process, ('process', ))
		self.tasks.run()
		
	def process(self, name):
		self.logger.debug("netflow normalized queue contains: " +
						  str(netflow_normalized_queue.qsize()) + " entries")
		
		try:
			protocol = "http://"
					
			if(self.options.ssl):
				protocol = "https://"
			
			while(not netflow_normalized_queue.empty()):
				netFlows = []
				
				while(not netflow_normalized_queue.empty()):
					netFlow = netflow_normalized_queue.get_nowait()
					self.logger.debug("start: " +
									  str(netFlow["first_switched"]) + " " +
									  netFlow["source"] + " -> " + netFlow["destination"] +
									  " duration: " +
									  str(netFlow["last_switched"] - netFlow["first_switched"]))

					# for accuracy, the below should be handled elsewhere
					if((netFlow["last_switched"] - netFlow["first_switched"]) > 600000):
						self.logger.debug("adjusting flow duration to maximum of 10 minutes")
						netFlow["first_switched"] = (netFlow["last_switched"] - 60000)

					jflow = {
						"byteSize": netFlow["in_bytes"] + netFlow["out_bytes"],
						"packetCount": netFlow["in_pkts"] + netFlow["out_pkts"],
						"destination": netFlow["destination"],
						"source": netFlow["source"],
						"protocol": netFlow["protocol"],
						"destinationPort": netFlow["dport"],
						"sourcePort": netFlow["sport"],
						"flags": netFlow["tcp_flags"],
						"startTimeStampMs": netFlow["first_switched"],
						"lastTimeStampMs": netFlow["last_switched"]
					}

					netFlows.append(jflow)
				
				if(len(netFlows) > 0):
					self.logger.debug("Preparing to send netFlows: " +
									  str(len(str(netFlows))))

					headers = {'content-type': 'application/json'}
					response = requests.put(protocol + self.args[0] + ":" +
											self.options.remote + "/flow/" + self.args[1],
											data=json.dumps(netFlows),
											headers=headers)
					
					self.logger.debug("Transfer completed.")
					self.logger.debug("Response: " + response.text)
					
		except URLError:
			self.logger.error("Unable to connect to Analysis Server from netflow" +
							  " transfer thread")
		except:
			self.logger.error(sys.exc_info())
			sys.exc_clear()
			
		if(not self.stop_flag):
			self.tasks.enter(5, 1, self.process, ('process', ))
			
	def stop(self):
		self.stop_flag = True

class NetflowQueueProcessor(Thread):
	
	def __init__(self, logger):
		Thread.__init__(self)
		self.logger = logger
		self.tasks = scheduler(time.time, time.sleep)
		self.stop_flag = False
		self.templates = {}

	fields = { 1:"in_bytes", 2:"in_pkts", 3:"netFlows", 4:"protocol", 6:"tcp_flags",
			   7:"sport", 8:"source", 9:"smask", 11:"dport", 12:"destination",
			   21:"last_switched", 22:"first_switched", 23:"out_bytes", 24:"out_pkts",
			   27:"source", 28:"destination", 60:"version" }
		
	def run(self):
		self.tasks.enter(5, 1, self.process, ('process', ))
		self.tasks.run()
		
	def process(self, name):
		self.logger.debug("netflow raw queue contains: " + str(netflow_queue.qsize()) +
						  " entries")
		
		retry = []
		while(not netflow_queue.empty()):
			sender, data = netflow_queue.get_nowait()
			version = self.parse_number(data[:2])
			count = self.parse_number(data[2:4])
			uptime = self.parse_number(data[4:8])
			epoch = self.parse_number(data[8:12])

			if(version == 9):
				result = self.v9(sender, count, epoch, uptime, data)
				if(result != None):
					self.logger.debug("queued flow from " + sender + " for retry")
					retry.append(result)
					
		for netflow in retry:
			netflow_queue.put((sender, netflow))
				
		if(not self.stop_flag):
			self.tasks.enter(5, 1, self.process, ('process', ))
			
	def v9(self, sender, count, epoch, uptime, data):
		sequence = self.parse_number(data[12:16])
		source = self.parse_number(data[16:20])

		flowsets = data[20:]
		
		counter = 0
		while(counter < count):
			id = self.parse_number(flowsets[:2])
			length = self.parse_number(flowsets[2:4])
			
			flowset = flowsets[:length]
			flowsets = flowsets[length:]

			if(id == 0):
				counter += self.parse_flow_templates(sender, flowset)
			elif(id == 1):
				counter += self.parse_options_templates(sender, flowset)
			elif((sender in self.templates.keys()) and (id in self.templates[sender].keys())):
				netflows = flowset[4:]
				
				if len(self.templates[sender][id]) != 0:
					while(counter < count and len(netflows) > 3):
						flow_size = 0
						counter += 1
					
						netflow = { "source":None, "destination":None, "protocol":None,
									"sport":None, "dport":None, "netFlows":None, "in_bytes":0,
									"out_bytes":0, "in_pkts":0, "out_pkts":0,
									"last_switched":None, "first_switched":None, "tcp_flags":0,
									"version":None }
					
						for type, location, size in self.templates[sender][id]:
							if type in self.fields:
								if (self.fields[type] == "source" or
									self.fields[type] == "destination"):
									netflow[self.fields[type]] = self.parse_address(
										netflows[location:location + size])
								elif (self.fields[type] == "last_switched" or
									  self.fields[type] == "first_switched"):
									netflow[self.fields[type]] = ((epoch * 1000) - uptime +
																  self.parse_number(
																	  netflows[location:location +
																			size]))
								else:
									netflow[self.fields[type]] = self.parse_number(
										netflows[location:location + size])
					    
							flow_size += size
								
						netflow_normalized_queue.put(netflow)	
						netflows = netflows[flow_size:]
				else:
					counter += 1
			else:
				counter = count
				self.logger.debug("couldn't find template for sender: " +
								  sender + ", id: " + str(id))
				return data
		return None
		
	def parse_address(self, data):
		if(len(data) == 16):
			return str(inet_ntop(AF_INET6, data))
		elif(len(data) == 4):
			return str(inet_ntop(AF_INET, data))
		else:
			return ""
			
	def parse_number(self, data):
		if(len(data) == 1):
			return unpack("!B", data)[0]
		if(len(data) == 2):
			return unpack("!H", data)[0]
		elif(len(data) == 4):
			return unpack("!I", data)[0]
			
	def parse_flow_templates(self, sender, data):
		template_count = 0
		
		while(len(data) > 0):
			template_count += 1
			flowset_id = self.parse_number(data[:2])
			length = self.parse_number(data[2:4])
			template_id = self.parse_number(data[4:6])
			field_count = self.parse_number(data[6:8])
			
			fields = []
			data = data[8:]

			if(not sender in self.templates.keys()):
				self.templates[sender] = {}
				
			count = 0
			location = 0
			while(count < field_count):
				count += 1
				type = self.parse_number(data[:2])
				length = self.parse_number(data[2:4])
				fields.append((type, location, length))
				location += length
				data = data[4:]
				
			self.templates[sender][template_id] = fields
			
		self.logger.debug("All Known Templates: " + str(self.templates))
		return template_count

	def parse_options_templates(self, sender, data):
		template_count = 0

		if(not sender in self.templates.keys()):
			self.templates[sender] = {}
								
		while(len(data) > 0):
			template_count += 1
			flowset_id = self.parse_number(data[:2])
			length = self.parse_number(data[2:4])
			template_id = self.parse_number(data[4:6])
			
			fields = []
			self.templates[sender][template_id] = fields
			data = data[length:]
			
		self.logger.debug("All Known Templates: " + str(self.templates))
		return template_count
	
	def stop(self):
		self.stop_flag = True

class NetflowCollector(SocketServer.DatagramRequestHandler):
	def handle(self):
		data = self.rfile.read(4096)
		client = self.client_address[0]
		netflow_queue.put((client, data))
		
	def finish(self):
		pass

class IPv6UDPServer(SocketServer.UDPServer):
	address_family = AF_INET6

class NetflowProcessor(Thread):
	def __init__(self, logger, args, options):
		Thread.__init__(self)
		self.logger = logger
		self.args = args
		self.options = options
		self.server = None
		self.stop_flag = False

		self.normalizer = NetflowQueueProcessor(self.logger)
		self.transfer = TransferThread(self.logger, self.args, self.options)
		
	def run(self):
		self.logger.info("Starting netflow normalizer and transfer threads")
		self.normalizer.start()
		self.transfer.start()
		
		self.server = IPv6UDPServer(("::", int(self.options.netflow_port)),
									NetflowCollector)
		self.server.serve_forever()
			
	def stop(self):
		self.logger.info("Stopping netflow processor...")
		
		if(self.server != None):
			self.server.shutdown()
			
		self.normalizer.stop()
		self.transfer.stop()
		self.normalizer.join()
		self.transfer.join()
		self.logger.info("netflow processor thread completed.")
