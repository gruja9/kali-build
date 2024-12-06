#!/bin/bash

# This tool will perform initial reconnaissance in an AD assessment utilizing Nmap and Nxc
# vikprg

if [ $# -ne 1 ]
then
	echo "Usage: $0 <domain>"
exit
domain=$1

# Configurations
scopeFolder="/home/kali/Pentest/Scope"
scansFolder="/home/kali/Pentest/Scans"
nmapFolder="/home/kali/Pentest/Scans/Nmap"
nxcFolder="/home/kali/Pentest/Scans/Nxc"
webPorts="80,443,8080,8443,8081,8082,8083,8084,8085,8888"

# Ping Scan
nmap -iL "$scopeFile/scope.txt" -sn -oN "$nmapFolder/ping.nmap" -n >/dev/null
cat "$nmapFolder/ping.nmap" | grep "scan report" | cut -d " " -f5 > "$scopeFolder/alive-ips.txt"

# Web Port Scan
nmap -iL "$scopeFolder/alive-ips.txt" -T3 -p $webPorts -oN "$nmapFolder/web.nmap" -oX "$nmapFolder/web.xml" -R --open

# Nxc Scans

## SMB
nxc smb "$scopeFolder/alive-ips.txt" > "$nxcFolder/smb-all.nxc"
cat "$nxcFolder/smb-all.nxc" | grep -i windows > "$nxcFolder/smb-all-windows.nxc"
cat "$nxcFolder/smb-all.nxc" | grep -i windows | grep $domain > "$nxcFolder/smb-all-windows-$domain.nxc"
cat "$nxcFolder/smb-all.nxc" | grep -i windows | grep $domain | grep -i server > "$nxcFolder/smb-all-windows-$domain-servers.nxc"

cat "$nxcFolder/smb-all-windows-$domain-servers.nxc" | awk -F' ' '{ print $2 }' > "$scansFolder/smb-$domain-servers-ips.txt"
cat "$nxcFolder/smb-all-windows-$domain.nxc" | awk -F' ' '{ print $2 }' > "$scansFolder/smb-$domain-ips.txt"

cat "$nxcFolder/smb-all-windows-$domain-servers.nxc" | grep signing:False | awk -F' ' '{ print $2 }' > "$scansFolder/smbrelaying-servers.txt"
cat "$nxcFolder/smb-all-windows-$domain.nxc" | grep signing:False | awk -F' ' '{ print $2 }' > "$scansFolder/smbrelaying.txt"

cat "$nxcFolder/smb-all-windows-$domain.nxc" | grep SMBv1:True | awk -F' ' '{print $2 }' > "$scansFolder/smbv1-ips.txt"

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
cat "$nxcFolder/rdp.nxc" | awk -F' ' '{ print $3 }' > "$scansFolder/rdp-ips.txt"