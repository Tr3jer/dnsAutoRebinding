#!/usr/bin/env python
#coding:utf-8
#Author = CongRong(@Tr3jer)

import ipaddr
import dnslib
import optparse
import SocketServer
from lib import common

class dnsAutoRebinding(SocketServer.UDPServer):
	def __init__(self,options):
		SocketServer.UDPServer.__init__(self, ('0.0.0.0', 53), self.sHandle)
		self.timeout = 3
		self.options = options

	def handle_timeout(self):
		print("handle timeout.")

	class sHandle(SocketServer.DatagramRequestHandler):
		def __init__(self,*args,**kwargs):
			SocketServer.DatagramRequestHandler.__init__(self, *args, **kwargs)

		def handle(self):
			record = ''
			ttl = int(common.conf_read('ttl'))
			record_type = common.conf_read('type')
			rebinding = common.conf_read('rebinding')
			rebindflag = int(common.conf_read('rebindflag'))

			client = self.client_address
			req = dnslib.DNSRecord.parse(self.packet).reply()
			qname = req.q.qname.__str__()

			if rebinding != 'False' and rebindflag == 1:
				if rebinding == 'True': record = client[0]
				else: record = rebinding
				common.conf_set({"rebindflag": "2"})
			else:
				record = common.analy_req(qname)
				common.conf_set({"rebindflag": "1"})

			try:
				if record:
					req.add_answer(dnslib.RR(qname, eval('dnslib.QTYPE.{}'.format(record_type)),rdata=eval('dnslib.{}(record)'.format(record_type)),ttl=ttl))
				else:
					print 'found query'
			except Exception,e:
				print e
				exit()

			print common.server_output(client,qname)
			self.wfile.write(req.pack())


	def run(self):
		print '[+] Set Config ...'
		common.conf_set(self.options)

		print '[+] Start Listening ...'
		self.serve_forever()

if __name__ == '__main__':
	parser = optparse.OptionParser('usage: sudo python main.py {Options}')
	parser.add_option('-t','--TTL',dest='ttl',help='ttl value , 0 By Default',default=0,type=int,metavar='300')
	parser.add_option('-y', '--Type', dest='record_type', help='Record Type , A By Default', default='A',type=str, metavar='A/AAAA/CNAME/MX')
	parser.add_option('-e','--Encoding',dest='encoding',help='Record Encoding , None By Default',default=None,type=str,metavar='int/hex/en')
	parser.add_option('-r','--Rebinding',dest='rebinding',help='The Second Time Query Return Target Ip',action='store_true',default=False)
	parser.add_option('-p','--payload',dest='payload',help='Specified Record , Support CNAME/MX',type=str,metavar='<script>alert(/xss/)</script>www.google.com')

	(options, args) = parser.parse_args()
	options.record_type = options.record_type.upper()

	if options.payload and options.record_type not in ['CNAME','MX']:
		print '[!] Please Specified Record Type , CNAME or MX'
		exit()

	if options.record_type == 'AAAA' and options.encoding not in ['hex','int']:
		print '[!] Please Specified Encoding , hex or int'
		exit()

	if options.rebinding:
		rand = raw_input("Input Safe Ip? [Address/Req By Default]")
		try:
			if ipaddr.IPAddress(rand).version in [4,6]:
				options.rebinding = rand
		except:
			pass

	dnsAutoRebinding(options).run()