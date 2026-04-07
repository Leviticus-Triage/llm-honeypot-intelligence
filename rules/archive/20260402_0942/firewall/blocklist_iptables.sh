#!/bin/bash
# LLM Honeypot Intelligence - Firewall Blocklist
# Generated: 2026-04-02 09:42 UTC
# Total: 502 IPs | Blocked: 30 scanners + 36 repeat + 108 active

# Mass Scanners (known infrastructure)
iptables -A INPUT -s 74.82.47.4 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 80.82.77.33 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 167.94.146.54 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 184.105.139.68 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 184.105.247.252 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.94 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.204 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.51 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.61 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.63 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 184.105.247.196 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 184.105.247.254 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.169 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.217 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.228 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.53 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.79 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.82 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.83 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.163 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.198 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.245 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.248 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.92 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 80.82.77.139 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.53 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 167.94.146.57 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 167.94.146.62 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 184.105.139.70 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 184.105.139.74 -j DROP  # scanner, 1 hits

# Repeat Offenders (>= 10 hits)
iptables -A INPUT -s 85.11.167.11 -j DROP  # 411 hits
iptables -A INPUT -s 134.199.196.64 -j DROP  # 182 hits
iptables -A INPUT -s 134.209.166.254 -j DROP  # 181 hits
iptables -A INPUT -s 122.168.194.41 -j DROP  # 168 hits
iptables -A INPUT -s 85.217.140.43 -j DROP  # 153 hits
iptables -A INPUT -s 204.76.203.231 -j DROP  # 114 hits
iptables -A INPUT -s 129.212.184.91 -j DROP  # 76 hits
iptables -A INPUT -s 23.95.55.242 -j DROP  # 62 hits
iptables -A INPUT -s 45.205.1.110 -j DROP  # 56 hits
iptables -A INPUT -s 119.179.249.148 -j DROP  # 46 hits
iptables -A INPUT -s 142.93.48.150 -j DROP  # 39 hits
iptables -A INPUT -s 157.230.159.118 -j DROP  # 39 hits
iptables -A INPUT -s 69.164.213.201 -j DROP  # 39 hits
iptables -A INPUT -s 85.217.140.22 -j DROP  # 35 hits
iptables -A INPUT -s 18.218.118.203 -j DROP  # 29 hits
iptables -A INPUT -s 85.217.140.50 -j DROP  # 29 hits
iptables -A INPUT -s 45.205.1.5 -j DROP  # 28 hits
iptables -A INPUT -s 16.58.56.214 -j DROP  # 24 hits
iptables -A INPUT -s 92.63.197.22 -j DROP  # 24 hits
iptables -A INPUT -s 46.151.178.13 -j DROP  # 22 hits
iptables -A INPUT -s 92.118.39.30 -j DROP  # 16 hits
iptables -A INPUT -s 3.130.168.2 -j DROP  # 15 hits
iptables -A INPUT -s 31.14.32.8 -j DROP  # 15 hits
iptables -A INPUT -s 45.142.154.31 -j DROP  # 14 hits
iptables -A INPUT -s 45.142.154.93 -j DROP  # 14 hits
iptables -A INPUT -s 45.205.1.26 -j DROP  # 14 hits
iptables -A INPUT -s 85.217.140.52 -j DROP  # 13 hits
iptables -A INPUT -s 106.75.13.142 -j DROP  # 12 hits
iptables -A INPUT -s 3.132.26.232 -j DROP  # 12 hits
iptables -A INPUT -s 45.82.78.104 -j DROP  # 12 hits
iptables -A INPUT -s 85.217.140.48 -j DROP  # 12 hits
iptables -A INPUT -s 91.224.92.125 -j DROP  # 12 hits
iptables -A INPUT -s 31.14.32.4 -j DROP  # 11 hits
iptables -A INPUT -s 85.217.140.34 -j DROP  # 11 hits
iptables -A INPUT -s 13.86.116.180 -j DROP  # 10 hits
iptables -A INPUT -s 3.131.220.121 -j DROP  # 10 hits

# Active Attackers (>= 3 hits)
iptables -A INPUT -s 204.76.203.206 -j DROP  # 9 hits
iptables -A INPUT -s 123.58.200.147 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.202.244 -j DROP  # 9 hits
iptables -A INPUT -s 165.154.11.140 -j DROP  # 9 hits
iptables -A INPUT -s 36.255.220.245 -j DROP  # 9 hits
iptables -A INPUT -s 85.217.140.39 -j DROP  # 9 hits
iptables -A INPUT -s 85.217.140.41 -j DROP  # 9 hits
iptables -A INPUT -s 86.54.25.205 -j DROP  # 9 hits
iptables -A INPUT -s 91.92.21.135 -j DROP  # 9 hits
iptables -A INPUT -s 91.92.21.182 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.145.49 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.100 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.105 -j DROP  # 8 hits
iptables -A INPUT -s 93.123.109.117 -j DROP  # 8 hits
iptables -A INPUT -s 115.231.78.11 -j DROP  # 7 hits
iptables -A INPUT -s 176.65.139.106 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.5.18 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.5.49 -j DROP  # 7 hits
iptables -A INPUT -s 185.226.197.37 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.117 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.17 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.50 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.217 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.83 -j DROP  # 7 hits
iptables -A INPUT -s 89.190.156.94 -j DROP  # 7 hits
iptables -A INPUT -s 98.80.4.101 -j DROP  # 7 hits
iptables -A INPUT -s 109.105.210.53 -j DROP  # 6 hits
iptables -A INPUT -s 18.116.101.220 -j DROP  # 6 hits
iptables -A INPUT -s 79.124.59.78 -j DROP  # 6 hits
iptables -A INPUT -s 106.75.12.4 -j DROP  # 5 hits
iptables -A INPUT -s 185.226.197.27 -j DROP  # 5 hits
iptables -A INPUT -s 20.65.195.33 -j DROP  # 5 hits
iptables -A INPUT -s 3.129.187.38 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.18 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.46 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.129.100 -j DROP  # 5 hits
iptables -A INPUT -s 93.174.95.106 -j DROP  # 5 hits
iptables -A INPUT -s 95.214.52.233 -j DROP  # 5 hits
iptables -A INPUT -s 109.105.210.52 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.149.105 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.201 -j DROP  # 4 hits
iptables -A INPUT -s 170.39.218.32 -j DROP  # 4 hits
iptables -A INPUT -s 176.65.139.105 -j DROP  # 4 hits
iptables -A INPUT -s 185.226.196.12 -j DROP  # 4 hits
iptables -A INPUT -s 185.226.197.30 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.129.101 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.103 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.106 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.108 -j DROP  # 4 hits
iptables -A INPUT -s 45.87.249.40 -j DROP  # 4 hits
iptables -A INPUT -s 47.74.5.117 -j DROP  # 4 hits
iptables -A INPUT -s 5.187.35.142 -j DROP  # 4 hits
iptables -A INPUT -s 65.49.1.24 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.98 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.144 -j DROP  # 4 hits
iptables -A INPUT -s 14.103.71.217 -j DROP  # 3 hits
iptables -A INPUT -s 141.98.10.108 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.178 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.166 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.31 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.40 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.196.15 -j DROP  # 3 hits
iptables -A INPUT -s 193.142.146.230 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.15 -j DROP  # 3 hits
iptables -A INPUT -s 199.45.154.126 -j DROP  # 3 hits
iptables -A INPUT -s 20.65.192.160 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.18 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.4 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.136.243 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.176.193 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.28.178 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.54.58 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.144.161 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.101.233 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.114.93 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.122.183 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.176.101 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.246.67 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.29.239 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.30.255 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.233.17 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.109.110 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.134.255 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.141.248 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.202.133 -j DROP  # 3 hits
iptables -A INPUT -s 64.62.156.24 -j DROP  # 3 hits
iptables -A INPUT -s 65.49.1.122 -j DROP  # 3 hits
iptables -A INPUT -s 65.49.1.66 -j DROP  # 3 hits
iptables -A INPUT -s 65.49.1.94 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.168 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.91 -j DROP  # 3 hits
iptables -A INPUT -s 77.90.185.16 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.126.67 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.238.181 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.83.9 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.157.244 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.16.2 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.3.150 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.8.182 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.8.47 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.9.246 -j DROP  # 3 hits
iptables -A INPUT -s 8.219.223.160 -j DROP  # 3 hits
iptables -A INPUT -s 91.231.89.134 -j DROP  # 3 hits
iptables -A INPUT -s 91.231.89.69 -j DROP  # 3 hits
iptables -A INPUT -s 91.92.21.169 -j DROP  # 3 hits
iptables -A INPUT -s 91.92.21.170 -j DROP  # 3 hits
iptables -A INPUT -s 91.92.21.171 -j DROP  # 3 hits
iptables -A INPUT -s 91.92.21.192 -j DROP  # 3 hits