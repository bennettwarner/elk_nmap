# ========================================================================================
# The code below has been adapted and tailored for this project.
# The original version can be found at: https://github.com/ChrisRimondi/VulntoES
# ========================================================================================
from elasticsearch import Elasticsearch
import sys
import re
import json
import time
import getopt
import codecs
import struct
import locale
import glob
import xml.etree.ElementTree as xml
from datetime import datetime

class NessusES:
	"This class will parse an Nessus v2 XML file and send it to Elasticsearch"

	def __init__(self, input_file,es_ip,es_port,index_name, static_fields):
		self.input_file = input_file
		self.tree = self.__importXML()
		self.root = self.tree.getroot()
		self.es = Elasticsearch([{'host':es_ip,'port':es_port}])
		self.index_name = index_name
		self.static_fields = static_fields
		vulnmapping = { "properties": {
					"pluginName": { "type": "string", "fields": {
						"raw": { "type": "string", "index": "not_analyzed" } } },
					"ip": { "type": "string", "fields": {
						"raw": { "type": "string", "index": "not_analyzed" } } },
					"risk_factor": { "type": "string", "fields": {
						"raw": { "type": "string", "index": "not_analyzed" } } },
					"severity": { "type": "integer" },
					"port": { "type": "integer" },
					"pluginFamily": { "type": "string", "fields": {
						"raw": { "type": "string", "index": "not_analyzed" } } },
					"plugin_type": { "type": "string", "fields": {
						"raw": { "type": "string", "index": "not_analyzed" } } },
					"svc_name": { "type": "string", "fields": {
						"raw": { "type": "string", "index": "not_analyzed" } } },
					"svcid": { "type": "string", "fields": {
						"raw": { "type": "string", "index": "not_analyzed" } } },
					"synopsis": { "type": "string", "fields": {
						"raw": { "type": "string", "index": "not_analyzed" } } },
					"solution": { "type": "string", "fields": {
						"raw": { "type": "string", "index": "not_analyzed" } } },
					} }
		mappings = { "mappings": { "vuln": vulnmapping } }

	def displayInputFileName(self):
		print(self.input_file)

	def __importXML(self):
		#Parse XML directly from the file path
		return xml.parse(self.input_file)

	def toES(self):
		"Returns a dict of dictionaries for each issue in the report"
		#Nessus root node only has 2 children. policy and report, we grab report here
		report = list(self.root)[1]
		dict_item={}
		#each child node of report is a report host - rh
		for rh in report:
			ip = rh.attrib['name']
			host_item={}
			#print rh.tag
			#iterate through attributes of ReportHost tags
			for tag in list(rh):
				dict_item={}
				if tag.tag == 'HostProperties':
					for child in list(tag):
						if child.attrib['name'] == 'HOST_END':
							host_item['time'] = child.text
							host_item['time'] = datetime.strptime(host_item['time'], '%a %b %d %H:%M:%S %Y')
							host_item['time'] = datetime.strftime(host_item['time'], '%Y/%m/%d %H:%M:%S')
						if child.attrib['name'] == 'operating-system':
							host_item['operating-system'] = child.text
						if child.attrib['name'] == 'mac-address':
							host_item['mac-address'] = child.text
						if child.attrib['name'] == 'host-fqdn':
							host_item['fqdn'] = child.text
						host_item['ip'] = ip
				elif tag.tag == 'ReportItem':
					dict_item['scanner'] = 'nessus'
					if tag.attrib['port']:
						dict_item['port'] = int(tag.attrib['port'])
					if tag.attrib['svc_name']:
						dict_item['svc_name'] = tag.attrib['svc_name']
					if tag.attrib['protocol']:
						dict_item['protocol'] = tag.attrib['protocol']
					if tag.attrib['severity']:
						dict_item['severity'] = tag.attrib['severity']
					if tag.attrib['pluginID']:
						dict_item['pluginID'] = tag.attrib['pluginID']
					if tag.attrib['pluginName']:
						dict_item['pluginName'] = tag.attrib['pluginName']
					if tag.attrib['pluginFamily']:
						dict_item['pluginFamily'] = tag.attrib['pluginFamily']
					#Iterate through child tags and texts of ReportItems
					#These are necessary because there can be multiple of these tags
					dict_item['cve'] = []
					dict_item['bid'] = []
					dict_item['xref'] = []
					for child in list(tag):
						#print child.tag
						if child.tag == 'solution':
							dict_item[child.tag] = child.text
						if child.tag == 'risk_factor':
							dict_item[child.tag] = child.text
						if child.tag == 'description':
							dict_item[child.tag] = child.text
						if child.tag == 'synopsis':
							dict_item[child.tag] = child.text
						if child.tag == 'plugin_output':
							dict_item[child.tag] = child.text
						if child.tag == 'plugin_version':
							dict_item[child.tag] = child.text
						if child.tag == 'see_also':
							dict_item[child.tag] = child.text
						if child.tag == 'xref':
							dict_item[child.tag].append(child.text)
						if child.tag == 'bid':
							dict_item[child.tag].append(child.text)
						if child.tag == 'cve':
							dict_item[child.tag].append(child.text)
						if child.tag == 'cvss_base_score':
							dict_item[child.tag] = float(child.text)
						if child.tag == 'cvss_temporal_score':
							dict_item[child.tag] = float(child.text)
						if child.tag == 'cvss_vector':
							dict_item[child.tag] = child.text
						if child.tag == 'exploit_available':
							if child.text == 'true':
								dict_item[child.tag] = 1
							else:
								dict_item[child.tag] = 0
						if child.tag == 'plugin_modification_date':
							dict_item[child.tag] = child.text
						if child.tag == 'plugin_type':
							dict_item[child.tag] = child.text
						try:
							ip = host_item['ip']
						except KeyError:
							ip = "-"

						try:
							protocol = dict_item['protocol']
						except KeyError:
							protocol = "-"

						try:
							port = dict_item['port']
						except KeyError:
							port = 0
						host_item['svcid'] = "%s/%s/%d" % (ip, protocol, port)

						for name in self.static_fields:
							dict_item[name] = self.static_fields[name]

				self.es.index(index=self.index_name, body=json.dumps(dict(list(host_item.items())+list(dict_item.items()))))


class NmapES:
	"This class will parse an Nmap XML file and send data to Elasticsearch"

	def __init__(self, input_file,es_ip,es_port,index_name):
		self.input_file = input_file
		self.tree = self.__importXML()
		self.root = self.tree.getroot()
		self.es = Elasticsearch([{'host':es_ip,'port':es_port}])
		self.index_name = index_name

	def displayInputFileName(self):
		print(self.input_file)

	def __importXML(self):
		# Parse XML directly from the file path
		return xml.parse(self.input_file)

	def toES(self):
		"Returns a list of dictionaries (only for open ports) for each host in the report"
		for h in self.root.iter('host'):
			dict_item = {}
			dict_item['scanner'] = 'nmap'
			if h.tag == 'host':
				if 'endtime' in h.attrib and h.attrib['endtime']:
					dict_item['time'] = time.strftime('%Y/%m/%d %H:%M:%S', time.gmtime(float(h.attrib['endtime'])))
			for c in h:
				if c.tag == 'address':
					if c.attrib['addr'] and c.attrib['addrtype'] == 'ipv4':
						dict_item['ip'] = c.attrib['addr']
					if c.attrib['addr'] and c.attrib['addrtype'] == 'mac':
						dict_item['mac'] = c.attrib['addr']

				elif c.tag == 'hostnames':
					for names in list(c):
						if names.attrib['name']:
							if 'hostname' in dict_item:
								dict_item['hostname'] = dict_item['hostname']+[names.attrib['name']]
							else:
								dict_item['hostname'] = [names.attrib['name']]
				elif c.tag == 'ports':
					for port in list(c):
						dict_item_ports = {}
						if port.tag == 'port':
							# print(port.tag, port.attrib)
							dict_item_ports['port'] = port.attrib['portid']
							dict_item_ports['protocol'] = port.attrib['protocol']
							for p in list(port):
								if p.tag == 'state':
									dict_item_ports['state'] = p.attrib['state']
								elif p.tag == 'service':
									for cpe in list(p):
										if cpe.tag == 'cpe':
											if 'cpe' in dict_item_ports:
												dict_item_ports['cpe'] = dict_item_ports['cpe']+[cpe.text]
											else:
												dict_item_ports['cpe'] = [cpe.text]
									dict_item_ports['service'] = p.attrib['name']
									if 'product' in p.attrib and p.attrib['product']:
										dict_item_ports['product_name'] = p.attrib['product']
										if 'version' in p.attrib and p.attrib['version']:
											dict_item_ports['product_version'] = p.attrib['version']
									if 'banner' in p.attrib and p.attrib['banner']:
										dict_item_ports['banner'] = p.attrib['banner']
								elif p.tag == 'script':
									if p.attrib['id']:
										try: 
											if p.attrib['output']:
												if 'scripts' in dict_item_ports:
													dict_item_ports['scripts'][p.attrib['id']] = p.attrib['output']
												else:
													dict_item_ports['scripts'] = dict()
													dict_item_ports['scripts'][p.attrib['id']] = p.attrib['output']
										except:
											print("Error: ", end="")
											print(p.attrib)

								for x in h:									
									if x.tag == 'hostscript':
										dict_item_hostscripts = {}
										for script in list(x):
											if script.tag == 'script':
												if script.attrib['id']:
													try: 
														if script.attrib['output']:
															if 'hostscripts' in dict_item_hostscripts:
																dict_item_hostscripts['hostscripts'][script.attrib['id']] = script.attrib['output']
															else:
																dict_item_hostscripts['hostscripts'] = dict()
																dict_item_hostscripts['hostscripts'][script.attrib['id']] = script.attrib['output']
													except:
														print("Error: ", end="")
														print(script.attrib)
										dict_item = merge_two_dicts(dict_item, dict_item_hostscripts)	
								
								to_upload = merge_two_dicts(dict_item, dict_item_ports)	
								# print(to_upload)
								if to_upload['state'] == 'open':
									self.es.index(index=self.index_name, body=json.dumps(to_upload))

def merge_two_dicts(x, y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z

def usage():
	print("Usage: ingestor.py [-i input_file | input_file=input_file] [-e elasticsearch_ip | es_ip=es_ip_address] [-p elasticsearch_port | es_port=es_server_port] [-I index_name] [-r report_type | --report_type=type] [-s name=value] [-h | --help]")

def main():
	letters = 'i:I:e:p:r:s:h' #input_file, index_name es_ip_address, report_type, create_sql, create_xml, help
	keywords = ['input-file=', 'index_name=', 'es_ip=','es_port=','report_type=', 'static=', 'help' ]
	try:
		opts, extraparams = getopt.getopt(sys.argv[1:], letters, keywords)
	except getopt.GetoptError as err:
		print(str(err))
		usage()
		sys.exit()
	
	in_file = ''
	es_ip = '127.0.0.1'
	es_port = 9200
	report_type = ''
	index_name = 'ingestor'
	static_fields = dict()

	for o,p in opts:
		if o in ['-i','--input-file=']:
			in_file = p
		elif o in ['-r', '--report_type=']:
			report_type = p
		elif o in ['-e', '--es_ip=']:
			es_ip=p
		elif o in ['-p', '--es_port=']:
			es_port=p
		elif o in ['-I', '--index_name=']:
			index_name=p
		elif o in ['-s', '--static']:
			name, value = p.split("=", 1)
			static_fields[name] = value
		elif o in ['-h', '--help']:
			usage()
			sys.exit()

	if (len(sys.argv) < 1):
		usage()
		sys.exit()

	try:
		with open(in_file) as f: pass
	except IOError as e:
		print("Input file does not exist. Exiting.")
		sys.exit()

	if report_type.lower() == 'nmap':
		print("Sending Nmap data to Elasticsearch")
		np = NmapES(in_file,es_ip,es_port,index_name)
		np.toES()
		print("Import complete!")
	elif report_type.lower() == 'nessus':
		print("Sending Nessus data to Elasticsearch")
		np = NessusES(in_file,es_ip,es_port,index_name, static_fields)
		np.toES()
		print("Import complete!")
	else:
		print("Error: Invalid report type specified. Available options: nmap or nessus")
		sys.exit()

if __name__ == "__main__":
	main()
