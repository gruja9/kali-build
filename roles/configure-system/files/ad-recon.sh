#!/bin/bash

# This tool will perform initial reconnaissance in an AD assessment utilizing Nmap and Nxc

if [ $# -ne 1 ]
then
	echo "Usage: $0 <domain>"
	exit
fi
domain=$1

# Configurations
pentestFolder="$HOME/Pentest"
scopeFolder="$pentestFolder/Scope"
scansFolder="$pentestFolder/Scans"
nmapFolder="$pentestFolder/Scans/Nmap"
nxcFolder="$pentestFolder/Scans/Nxc"
reportFolder="$pentestFolder/Report"
webPorts="80,443,8080,8443,8081,8082,8083,8084,8085,8888"

# Ping Scan
nmap -iL "$scopeFolder/scope.txt" -sn -PS445 -PA445 -oN "$nmapFolder/ping.nmap" -n >/dev/null
cat "$nmapFolder/ping.nmap" | grep "scan report" | cut -d " " -f5 > "$scopeFolder/alive-ips.txt"

# Web Port Scan
nmap -iL "$scopeFolder/alive-ips.txt" -T3 -p $webPorts -oN "$nmapFolder/web.nmap" -oX "$nmapFolder/web.xml" -R --open >/dev/null

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