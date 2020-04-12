# Script to extract IP, URL and hashes from PDF file
# Use Python 3
# Use iocextract library

import os
import sys
import argparse
import iocextract
# import PyPDF2
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.pdfpage import PDFPage
from io import StringIO
# imports for ip lookup
import ipwhois
import csv

'''
This function extracts ip address, urls and hashes from a input file
and stores the results in the directory of the given output file
'''
def extract(filein, fileout):

 	# Setting up extractation of text from pdf
	rsrcmgr = PDFResourceManager()
	retstr = StringIO()
	codec = 'utf-8'  # 'utf16','utf-8'
	laparams = LAParams()
	device = TextConverter(rsrcmgr, retstr, codec=codec, laparams=laparams)

	# open file
	f = open(filein, mode='rb')
	interpreter = PDFPageInterpreter(rsrcmgr, device)
	for page in PDFPage.get_pages(f):
		interpreter.process_page(page)
	f.close()
	device.close()
	text = retstr.getvalue()
	retstr.close()

	with open(fileout+".csv","w",newline="") as file:
		writer = csv.writer(file)
		writer.writerow(["IP","ASN","Country Code"])
		for ip in iocextract.extract_ips(text, refang=True):
			print(ip)
			try:
				ans = resolveIP(ip)
			except:
				print("An error has occured")
			writer.writerow(ans)
	file.close()
	return



'''
This function resolves IP address 
Returns a list with the ip, asn and country code

'''
def resolveIP(ip):
	#  make whois query to find ASN and country code
	result = None
	obj = ipwhois.IPWhois(ip)
	try:
		rdap_answer = obj.lookup_rdap(depth=1)
	except ipwhois.exceptions.BaseIpwhoisException as e:
		return e
	else:
		result = [ip, rdap_answer.get("asn"),  rdap_answer.get("asn_country_code")]

	return result

if __name__== "__main__":
	# set up the argument parser
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', dest='input',help='input file')
	parser.add_argument('-o', dest='output', help='output file')

	# parse our arguments
	args = parser.parse_args()
	filein=args.input
	fileout=args.output

	if (filein == "" or filein == None or fileout == "" or fileout == None ):
		print("Please input a valid file path")
		print("usage: script.py [-h] [-i INPUT] [-o OUTPUT]")
		print("output file will be automatically saved as a CSV file")
		sys.exit(2)

	extract(filein, fileout)
