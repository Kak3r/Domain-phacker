# Domain-phacker
Automatic tool for penetration testing and security assessment of Active Directory Domain environment.
 

The tool checks:
1. All shared passwords in the domain 
2. Domain Admins with weak passwords
3. Number of domain admins
4. Build histograms
5. Crack defualt passwords
6. Check for Eternal_blue Vanurable IP's 

How it works:

1. Using Impacket secretsdump it gets local copy on ntds.dit
2. Using ropnop windpasearch LDAP gets Domain Admins
3. Using Worawit ms17-010 checks for Eternal Blue

Usage: Domain_phacker.py <DC_IP> <User> <Password> <IP_list> <outputfile>

User must be Domain Admin
IP list of computers you want to check for Eternal Blue



