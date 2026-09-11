#!/bin/bash

# This tool will perform initial reconnaissance in an AD assessment utilizing Nmap and Nxc

if [ $# -ne 1 ]
then
	echo "Usage: $0 <domain>"
	exit
fi
domain=$1

alias gowitness='docker run --rm -v `pwd`:/data -p7171:7171 leonjza/gowitness gowitness'

# Configurations
pentestFolder="$HOME/Pentest"
scopeFolder="$pentestFolder/Scope"
scansFolder="$pentestFolder/Scans"
nmapFolder="$pentestFolder/Scans/Nmap"
nxcFolder="$pentestFolder/Scans/Nxc"
reportFolder="$pentestFolder/Report"
ports="21,22,23,53,80,88,389,443,445,1433,1521,1666,2049,2375,2376,3000,3306,3389,5000,5432,5601,5900,6379,6443,7001,7990,8000,8080,8081,8082,8161,8443,8530,8531,8888,8929,9000,9001,9090,9100,9101,9200,9443,10123,15672,27017,u:161,u:623"

# Nmap Ping Scan
#nmap -iL "$scopeFolder/scope.txt" -sn -PS445 -PA445 -n -oN "$nmapFolder/ping.nmap" >/dev/null
#cat "$nmapFolder/ping.nmap" | grep "scan report" | cut -d " " -f5 > "$scopeFolder/alive-ips.txt"

# Web Port Scan
#nmap -iL "$scopeFolder/alive-ips.txt" -T3 -p $webPorts -oN "$nmapFolder/web.nmap" -oX "$nmapFolder/web.xml" -R --open >/dev/null

# Naabu Ping Scan
mapcidr -cl "$scopeFolder/scope.txt" -silent > "$scopeFolder/scope-ips.txt"
sudo ~/go/bin/naabu -silent -l "$scopeFolder/scope-ips.txt" -sn -wn -ps 80,443,445,3389,5985 -pa 80,443,445,3389,5985 -pe -arp -iv 4 > "$scopeFolder/alive-ips.txt"

# Naabu Port Scan
naabu -silent -l "$scopeFolder/alive-ips.txt" -p $ports -iv 4 -Pn > "$scansFolder/open-ports.csv"
cat "$scansFolder/open-ports.csv" | cut -d ":" -f1 > "$scopeFolder/alive-ips-ports.txt"

# Web Scans
~/go/bin/httpx -silent -l "$scopeFolder/alive-ips-ports.txt" -p $ports -o "$scansFolder/web.httpx" -ss -system-chrome
gowitness scan file -f /data/Pentest/Scans/web.httpx

# Nxc Scans

## SMB
nxc smb "$scopeFolder/alive-ips.txt" > "$nxcFolder/smb-all.nxc"
strings "$nxcFolder/smb-all.nxc" | grep -i windows > "$nxcFolder/smb-all-windows.nxc"
strings "$nxcFolder/smb-all.nxc" | grep -i windows | grep -i $domain > "$nxcFolder/smb-all-windows-$domain.nxc"
strings "$nxcFolder/smb-all.nxc" | grep -i windows | grep -i $domain | grep -i server > "$nxcFolder/smb-all-windows-$domain-servers.nxc"
strings "$nxcFolder/smb-all.nxc" | grep -vi windows > "$nxcFolder/smb-all-non-windows.nxc"

strings "$nxcFolder/smb-all-windows-$domain-servers.nxc" | awk -F' ' '{ print $2 }' > "$scansFolder/smb-$domain-servers-ips.txt"
strings "$nxcFolder/smb-all-windows-$domain.nxc" | awk -F' ' '{ print $2 }' > "$scansFolder/smb-$domain-ips.txt"
strings "$nxcFolder/smb-all-non-windows.nxc" | awk -F' ' '{ print $2 }' > "$scansFolder/smb-non-windows-ips.txt"

strings "$nxcFolder/smb-all-windows-$domain-servers.nxc" | grep signing:False | awk -F' ' '{ print $2 }' > "$scansFolder/smbrelaying-servers.txt"
strings "$nxcFolder/smb-all-windows-$domain.nxc" | grep signing:False | awk -F' ' '{ print $2 }' > "$scansFolder/smbrelaying.txt"
strings "$nxcFolder/smb-all-windows-$domain.nxc" | grep signing:False | awk -F' ' '{ print $2,$4 }' > "$reportFolder/smbrelaying.csv"

strings "$nxcFolder/smb-all-windows-$domain.nxc" | grep SMBv1:True | awk -F' ' '{print $2 }' > "$scansFolder/smbv1-ips.txt"
strings "$nxcFolder/smb-all-windows-$domain.nxc" | grep SMBv1:True | awk -F' ' '{ print $4 }' > "$reportFolder/smbv1.csv"

strings "$nxcFolder/smb-all-windows-$domain.nxc" | grep "Null Auth" | awk -F' ' '{print $2 }' > "$scansFolder/smb-windows-null-ips.txt"
strings "$nxcFolder/smb-all-non-windows.nxc" | grep "Null Auth" | awk -F' ' '{print $2 }' > "$scansFolder/smb-non-windows-null-ips.txt"
strings "$nxcFolder/smb-all-windows-$domain.nxc" | grep "Null Auth" | awk -F' ' '{ print $2,$4 }' > "$reportFolder/smb-null-auth.csv"

## FTP
nxc ftp "$scopeFolder/alive-ips.txt" | grep FTP > "$nxcFolder/ftp.nxc"
cat "$nxcFolder/ftp.nxc" | awk -F' ' '{ print $2 }' > "$scansFolder/ftp-ips.txt"

## SSH
nxc ssh "$scopeFolder/alive-ips.txt" | grep SSH > "$nxcFolder/ssh.nxc"
cat "$nxcFolder/ssh.nxc" | awk -F' ' '{ print $2 }' > "$scansFolder/ssh-ips.txt"

## MSSQL
nxc mssql "$scopeFolder/alive-ips.txt" | grep MSSQL > "$nxcFolder/mssql.nxc"
cat "$nxcFolder/mssql.nxc" | awk -F' ' '{ print $2 }' > "$scansFolder/mssql-ips.txt"

## RDP
nxc rdp "$scopeFolder/alive-ips.txt" | grep RDP > "$nxcFolder/rdp.nxc"
cat "$nxcFolder/rdp.nxc" | awk -F' ' '{ print $2 }' > "$scansFolder/rdp-ips.txt"

## VNC
#nxc vnc "$scopeFolder/alive-ips.txt" | grep VNC > "$nxcFolder/vnc.nxc"
#cat "$nxcFolder/vnc.nxc" | awk -F' ' '{ print $2 }' > "$scansFolder/vnc-ips.txt"

## NFS
#nxc nfs "$scopeFolder/alive-ips.txt" | grep NFS > "$nxcFolder/nfs.nxc"
#cat "$nxcFolder/nfs.nxc" | awk -F' ' '{ print $2 }' > "$scansFolder/nfs-ips.txt"

# Nuclei
~/go/bin/nuclei -l "$scopeFolder/alive-ips-ports.txt" -tags devops,cicd,jenkins,gitlab,kubernetes,docker,grafana,prometheus,mysql,postgres,mongodb,redis,mssql,wordpress,drupal,joomla,tomcat,weblogic -severity medium,high,critical -o "$scansFolder/vulns-devops.nuclei"
~/go/bin/nuclei -l "$scopeFolder/alive-ips-ports.txt" -tags default-login -severity info,low,medium,high,critical -o "$scansFolder/default-creds.nuclei"
~/go/bin/nuclei -l "$scopeFolder/alive-ips-ports.txt" -tags panel,dashboard,exposed,config -severity medium,high,critical -o "$scansFolder/exposed-panels.nuclei"
~/go/bin/nuclei -l "$scopeFolder/alive-ips-ports.txt" -tags cve -severity high,critical -o "$scansFolder/cves.nuclei"