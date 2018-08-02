import csv

def getGroups():
	groups = []
	with open ('output/groups.tsv') as tsvfile:
		reader = csv.reader(tsvfile,delimiter = '\t',quotechar= "'")
		for row in reader:
			try: 	
				groups.append(row[1])
			except:
				pass
		return groups

def get_admin_groups(groups):
	admins = []
	for i in groups:
		if "admin" in i.lower():
			admins.append(i)
	return admins

def get_users():
	pass

def get_Domain_admins():
	domain_admins = []
	with open ('output/domainadmins.tsv') as tsvfile:
		reader = csv.reader(tsvfile,delimiter = '\t',quotechar= "'")
		for row in reader:
			domain_admins.append(row[0])
	return domain_admins


#print get_Domain_admins()
#groups = getGroups()
#admins = get_admin_groups(groups)
#for i in admins:
#	print i
#for i in group:
#	print group