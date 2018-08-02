"""Usage: Domain_phacker.py <DC> <User> <Password> <IP_list> <outputfile>"""
from docopt import docopt
import subprocess
from collections import Counter
import numpy as np
import matplotlib.pyplot as plt
import parse
import EB_checker
import os 

#default Passwords hash
DEFAULT_PASSWORDS = {"47bf8039a8506cd67c524a03ff84ba4e":"Aa123456","67587a19e4c2b479f1fa85b95b544229":"Bb123456"}

def exec_secrets_dump(User,Password,DC,outputfile):
	outputpath = "output/" + outputfile
	secretsdump_call = "python ./secretsdump.py {}:{}@{} -outputfile {}".format(User,Password,DC,outputpath) 
	subprocess.call(secretsdump_call,shell=True)

def count_shared_passwrods(ntds_file):

	file_path = "output/" + ntds_file + ".ntds"
	hashes = []
	hash =""
	with open(file_path, 'r') as file:
		try:
			hash = file.readline().split(":")[3]
			while hash:
				hashes.append(hash)
				hash = file.readline().split(":")[3]
		except:
			pass
	counter_hashes = Counter(hashes)
	keys = (filter(lambda x: counter_hashes[x] != 1,counter_hashes))
	return Counter({key: counter_hashes[key] for key in keys})


def show_histograms(shared_passwords,histogram_output):

	show_top = 5 
	lables = []
	most_common_passwords = dict(shared_passwords.most_common(show_top))			
	hashes,values = zip(*most_common_passwords.items())
	
	for i in hashes:
		if i in DEFAULT_PASSWORDS.keys():
			lables.append(DEFAULT_PASSWORDS[i])
		else:
			lables.append("hash -" + i[0:5])
	print lables

	indexes = np.arange(len(lables))
	width = 1 
	plt.bar(indexes, values, width)
	plt.xticks(indexes + width * 0.5, lables)
	plt.savefig("output/" + histogram_output + ".png")

def exec_get_groups_and_DA(User,Password,DC):
	AD_search_call = "python ./AD_search.py --dc-ip {} -u {} -p {} --da -G".format(DC,User,Password)
	subprocess.call(AD_search_call,shell=True)

def exec_get_users_from_group(groups,Password,dc):

	AD_search_call = "python ./AD_search.py --dc-ip {} -u {} -p {} --da -G".format(DC,User,Password)
	subprocess.call(AD_search_call,shell=True)



def get_strong_users():
# TODO!!!!!!!!!!!!!!!!!!!!
	admin_groups = parse.get_admin_groups()
	
def get_domain_admins():
	return parse.get_Domain_admins()	


def find_strong_users_with_weak_password(strong_users,ntds_file,shared_passwords):
	#print "*"*50
	#print strong_users
	file_path = "output/" + ntds_file + ".ntds"
	show_top = 5 
	most_common_passwords = dict(shared_passwords.most_common(show_top)).keys()	
	users_with_weak_password = {}
	with open(file_path, 'r') as file:
		try:
			line = file.readline()
			while line:
				try:
					user = line.split(":")[0].split("\\")[1]
					#print "*"*50
					#print user
				except:
					user = line.split(":")[0]
					#print "A"*50
					#print user
				if(user in strong_users):
					if line.split(":")[3] in most_common_passwords:
						users_with_weak_password[user] = line.split(":")[3]
				line = file.readline()
		except:
			pass	
	return users_with_weak_password

def check_for_EB(ip_list):
	#####NEED TO ADD threads####################
	vuln_machines = []
	with open(ip_list , 'r') as file:
		target = file.readline()
		while target:
				if(EB_checker.checker(target)):
					vuln_machines.append(target)
				target = file.readline()
	return vuln_machines


def output_file(output_name,domain_admins,DA_with_weak_passwords,shared_passwords,vuln_machines):
	file_path = "output/" + output_name + ".output"

	with open(file_path , 'w') as file:
		file.write("*" * 50 + "\n")

		file.write("shared_passwords \n")
		passwords = shared_passwords
		for key,value in passwords.most_common():
			hashes_and_occurences = "{} - {} \n".format(key, value)
			file.write(hashes_and_occurences)

		file.write("*" * 50 + "\n")
		file.write("Domain Admins \n")
		file.write("There Are {} Domain Admins \n".format(len(domain_admins)))
		for i in domain_admins:
			file.write(i + "\n")


		file.write("*" * 50 + "\n")
		file.write("Domain Admins with shared_password \n")
		file.write("There Are {} Domain Admins with shared passwords\n".format(len(DA_with_weak_passwords)))
		for i in DA_with_weak_passwords.keys():
			username_and_password = "{} - {} \n".format(i, DA_with_weak_passwords[i])
			file.write(username_and_password)

		file.write("*" * 50 + "\n")
		file.write("Machines vulnerable to ms17-10 \n")
		for i in vuln_machines:
			file.write(i + "\n")

if __name__ == '__main__':
	arguments = docopt(__doc__)
	if not os.path.exists("output"):
		os.makedirs("output")
	exec_secrets_dump(arguments['<User>'],arguments['<Password>'],arguments['<DC>'],arguments['<outputfile>'])
	shared_passwords =  count_shared_passwrods(arguments['<outputfile>'])
	print shared_passwords
	show_histograms(shared_passwords,arguments['<outputfile>'])
	exec_get_groups_and_DA(arguments['<User>'],arguments['<Password>'],arguments['<DC>'])
	domain_admins = get_domain_admins()
	DA_with_weak_passwords = find_strong_users_with_weak_password(domain_admins,arguments['<outputfile>'],shared_passwords)
	vuln_machines = check_for_EB(arguments['<IP_list>'])


	output_file(arguments['<outputfile>'],domain_admins, DA_with_weak_passwords,shared_passwords,vuln_machines)


	#strong_users = get_strong_users()
	#find_strong_users_with_weak_password(strong_users)
