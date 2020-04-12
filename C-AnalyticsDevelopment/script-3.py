# Script to search of supicious IP performing recon
# Use Python 3
# Use urllib.parse library to decode encoded values

import os
import sys
import argparse
import numpy as np
import csv
import urllib.parse

'''
This function shortlist IPs that could be running reconnaissance activities
'''
def extract(filein, fileout, errortT2, errortTB):

	# Run through data
	f = open(filein, mode="r", encoding="latin-1")

	'''
	Data
	ts, uid, src ip (2), src port(3), dst ip(4), dst port(5), trans depth, method, host, uri (9),
	referrer, user agent(11), request body len, response body len, status code(14),
	status msg(15), info code, info msg, filename (18), tags,
	username(20), password, proxied, orig fuids, orig mime types, 
	resp fuid, resp mime types
	'''
	# Store ip and their user agent
	ip_userAgent = {}
	# Store ip, server status code
	ip_Status = {}
	# Store ip with injections and path tranversal
	ip_injections_pathTrans = []
	# ip with script like encoding

	for _, line in enumerate(f):
		df = line.split("\t")
		# if len(df) != 27:
		# 	print(df)

		if (df[2] in ip_userAgent):
			ip_userAgent_inner = ip_userAgent.get(df[2]) 
			if df[11] in ip_userAgent_inner:
				ip_userAgent_inner[df[11]] +=1
			else:
				ip_userAgent_inner[df[11]] =1
		else:
			ip_userAgent[df[2]] = {df[11]:1}

		if (df[2] in ip_Status):
			ip_Status_inner = ip_Status.get(df[2])
				# We take the first number only as it is enough to tell us whether it is a succesful attempt or not
			if df[14][0] in ip_Status_inner:
				ip_Status_inner[df[14][0]] +=1
			else:
				ip_Status_inner[df[14][0]] = 1
			ip_Status_inner["Total"] +=1
		else:
			ip_Status[df[2]] = {df[14][0]:1, "Total":1}


		decoded = urllib.parse.unquote(line).lower()
		lower = line.lower()
		xss_sql = ["</script>", "<img", " or ", " and ", " union ", " insert ", " delete "]
		paths = ["../", "..\\", "..%2f", "..%2e", "..%5c", "%c0%ae","passwd","boot.ini", "shadow"]
		if any(xs in decoded for xs in xss_sql):
			# print(df[2], decoded)
			if (df[2] not in ip_injections_pathTrans):
				ip_injections_pathTrans.append(df[2])
		elif any(xs in lower for xs in paths):
			if (df[2] not in ip_injections_pathTrans):
				ip_injections_pathTrans.append(df[2])
	f.close()

	# Flag out IPs with more than 1 user agent
	# print("Total unique ip ", len(ip_userAgent))
	flagged_UA = []
	for k, v in ip_userAgent.items():
		# print(len(v))
		userAgents = v.keys()
		matchers = ['Wget', 'Nessus', 'Nmap', 'Googlebot']
		matching = [s for s in userAgents if any(xs in s for xs in matchers)]
		if len(v) > 1 or len(matching) != 0:
			flagged_UA.append(k)
			# print(v)
	# print(flagged_UA)	
	
	# Flag out IPs with low request success
	# print("Total unique ip ", len(ip_Status))
	flagged_Status = []
	for k, v in ip_Status.items():
		status = v.keys()
		# Check percentage
		if "2" in status and len(status) > 2:
			percent = v["2"]/v["Total"]
			if percent < errortT2:
				flagged_Status.append(k)
		elif "-" in status:
			percent = v["-"]/v["Total"]
			if percent > errortTB:
				flagged_Status.append(k)
		# print(k, v)
	# print(flagged_Status)

	# print(ip_injections_pathTrans)

	# Combine all IP addresses
	final_array = []
	combined = flagged_UA + flagged_Status + ip_injections_pathTrans
	for i in combined:
		if i not in final_array:
			final_array.append(i)
	
	with open(fileout+".txt","w", encoding="latin-1") as fout:
		for i in final_array:
			fout.write(i + "\n")
	fout.close()

	return



if __name__== "__main__":
	# set up the argument parser
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', dest='input',help='Input file')
	parser.add_argument('-o', dest='output', help='Output file')
	parser.add_argument('-errorT2', dest='errorT2', help='Optional, default:0.5; Error threshold for percentage of non 200s in status code', default=0.5)
	parser.add_argument('-errorTB', dest='errorTB', help='Optional, default:0.5; Error threshold for percentage of unknown status in status code', default=0.5)

	# parse our arguments
	args = parser.parse_args()
	filein=args.input
	fileout=args.output
	errorT2=float(args.errorT2)
	errorTB=float(args.errorTB)

	if (filein == "" or filein == None or fileout == "" or fileout == None ):
		print("Please input a valid file path")
		print("usage: script.py [-h] [-i INPUT] [-o OUTPUT] [<optional> -errorT2 -errorTB]")
		print("output file will be automatically saved as a txt file")
		sys.exit(2)

	extract(filein, fileout, errorT2, errorTB)
