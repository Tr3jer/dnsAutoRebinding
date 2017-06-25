#!/usr/bin/env python
#coding:utf-8

import sys
import time
import ipaddr
import ConfigParser

def analy_req(address):
	mainDomain = conf_read('maindomain')
	address = address[:-len(mainDomain) - 1]
	payload = conf_read('payload')
	encoding = conf_read('encoding')
	record = address

	try:

		if encoding == 'int':
			record = ipaddr.IPAddress(int(address)).__str__()
		elif encoding == 'hex':
			try:
				address = address.decode('hex')

				if ipaddr.IPAddress(address).version == 4:
					record = address
				elif conf_read('type') == 'AAAA' and ipaddr.IPAddress(address).version == 6:
					record = address
				else:
					pass
			except:
				pass
		# elif False not in map(lambda x:x in map(lambda x:chr(x),range(97,108)),list(address)):
		elif encoding == 'en':
			record = numToEnToNum(address)
		elif payload != 'None' and payload.find(mainDomain) == -1:
			# record = payload + "www.google.com"
			record = payload + mainDomain

	except Exception,e:
		print '[!] Subdomain Invalid {}'.format(e)
	finally:
		return record


def numToEnToNum(address):
	numToEn,enToNum = {},{}
	result = ''

	for k, v in enumerate(range(97, 108)):
		if k == 10: k = '.'
		numToEn[str(k)] = chr(v)
		enToNum[chr(v)] = str(k)

	try:
		if '.' in list(address):
			for i in list(address): result += numToEn[i]
		else:
			for i in list(address): result += enToNum[i]
	except:
		print '[!] address error'

	return result


def ipListBuild(address):
	print '1. Single IP Covert For En\n2. Build IP List'
	opt_req = raw_input("[+] [1 By Default/2]") or '1'
	if opt_req == '1':
		print numToEnToNum(address)
		exit()

	conf_main = conf_read('maindomain')[:-1]
	seg_len = raw_input("[+] Please Input Segment Length [24 By Default]") or 24
	encode_req = raw_input("[+] Please Input Encoding ['ipv4' By Default]")
	mainDomain = raw_input("[+] Please Input Server Root Address [{} By Default]".format(conf_main)) or conf_main
	segment = eval("ipaddr.IPv4Network('{}/{}').iterhosts()".format(address, int(seg_len)))
	save_file = "{}_{}_{}.txt".format(time.strftime("%Y%m%d%X", time.localtime()).replace(':', ''), mainDomain.replace('.','_'),(encode_req if encode_req else 'ipv4'))
	results = []

	try:

		if encode_req == '': results += ["{}.{}".format(str(i),mainDomain) for i in list(segment)]
		elif encode_req == 'en':
			results += ["{}.{}".format(numToEnToNum(str(i)),mainDomain) for i in list(segment)]
		elif encode_req == 'int':
			results += ["{}.{}".format(int(ipaddr.IPAddress(str(i))),mainDomain) for i in list(segment)]
		elif encode_req == 'hex':
			results += ["{}.{}".format(str(i).encode('hex'),mainDomain) for i in list(segment)]
		else:
			pass

		f = open(save_file,'a')
		[f.write(i+'\n') for i in results]
		f.close()
		print '[+] Stored in the {}'.format(save_file)
	except Exception,e:
		print e
		exit()


def server_output(*args):
	client_ip = args[0][0]
	client_port = args[0][1]
	req_address = args[1]
	flag = "[{}] {}:{} => {} => {}".format(time.strftime("%X",time.localtime()),client_ip,client_port,conf_read('type'),req_address)

	return flag


def conf_read(*args):
	config = ConfigParser.ConfigParser()
	with open('lib/config.conf', 'rw') as conf:
		config.readfp(conf)
		if args:
			return config.get('base',args[0])
		else:
			return config


def conf_set(options):
	config = conf_read()

	if '__class__' in dir(options):
		for k,v in options.items(): config.set('base',k,v)
	else:
		config.set('base','type',options.record_type)
		config.set('base','payload',options.payload.__str__())
		config.set('base','encoding',options.encoding)
		config.set('base','rebinding',options.rebinding.__str__())

	if config.get('base','maindomain')[-1:] != '.':
		config.set('base','maindomain',config.get('base','maindomain')+'.')
	with open('lib/config.conf','w+') as f:
		config.write(f)


if __name__ == '__main__':

	if len(sys.argv) > 1:
		ipListBuild(sys.argv[1])
	else:
		print '[+] Please Input Ip'
		exit()
