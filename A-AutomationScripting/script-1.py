# Script to extract IP, URL and hashes from PDF file
# Use Python 3
# Use iocextract library

import os
import re
import sys
import argparse
import iocextract
# import PyPDF2
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.pdfpage import PDFPage
from io import StringIO

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

	# open/create output file
	fout = open(fileout+".txt", mode="wb")

	fout.write(b"=== IP ===\n")
	for ip in iocextract.extract_ips(text, refang=True):
		# print(ip)
		fout.write(ip.encode("latin-1")+ b"\n")

	fout.write(b"=== URL ===\n")
	for url in iocextract.extract_urls(text, refang=True):
		# print(url)
		fout.write(url.encode("latin-1")+ b"\n")

	fout.write(b"=== Hashes ===\n")
	for _hash in iocextract.extract_hashes(text):
		# print(_hash)
		fout.write(_hash.encode("latin-1")+ b"\n")

	fout.close()
	return


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
		print("output file will be automatically saved as a txt file")
		sys.exit(2)

	extract(filein, fileout)
