#!/usr/bin/python
import socket, ssl
import argparse

def get_args():
    p = argparse.ArgumentParser(description="CERT Alt Hostname Grabber")
    p.add_argument('-u','--url',type=str,help="Target URL Hostname:  google.com")
    p.add_argument('-f','--file',type=argparse.FileType('r'), help="File of target IPs")

    args = p.parse_args()

    return args

def get_Hostnames(hostname):
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

    context = ssl.create_default_context()
    context.check_hostname = False
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)
    #conn._https_verify_certificates(enable=False)
    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    # parse the string from the certificate into a Python datetime object
    return ssl_info['subjectAltName']

def getter(myhost):
    domains = []
    try:
        hostnames = get_Hostnames(myhost)
        for index, tuple in enumerate(hostnames):
            domain = tuple[1].split('.')[-2] + "." + tuple[1].split('.')[-1]
            if domain not in domains:
                domains.append(domain)
        return domains
    except Exception as e:
        print ("[*] Connection Failed")
        return ["Failed"]

def save_to_disk(_list):
    f = open('cert-domains.txt','a+')
    for x in _list:
        f.write(x+"\r\n")
    f.close()
    print ("[*] Domains saved to .\cert-domains.txt")

def main():
    args = get_args()

    final = []

    if args.url:
        domains = getter(args.url)
        save_to_disk(domains)
        print ("[+] Number of Found Domains: %s" % str(len(domains)))
	exit()
    elif args.file:
        for target in args.file:
            domains = getter(target)
            for d in domains:
                final.append(d)
        save_to_disk(final)
        print ("[+] Number of Found Domains: %s" % str(len(domains)))
        exit()

    else:
        print ("[!] Must use '-u' or '-f'.  Look at help menu '-h'")
	exit()

if __name__ == '__main__':
    main()
