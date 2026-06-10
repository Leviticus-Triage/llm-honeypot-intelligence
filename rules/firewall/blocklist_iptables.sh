#!/bin/bash
# LLM Honeypot Intelligence - Firewall Blocklist
# Generated: 2026-06-10 06:05 UTC
# Total: 515 IPs | Blocked: 44 scanners + 69 repeat + 280 active

# Mass Scanners (known infrastructure)
iptables -A INPUT -s 80.82.77.139 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.58 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.112 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.169 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.105 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.161 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.74 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 167.94.146.53 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 184.105.139.68 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.121 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.161 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.165 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.174 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.208 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.222 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.244 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.251 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.54 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.77 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.94 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.95 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.209 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.250 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.255 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.55 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 66.240.205.34 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.48 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.50 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.54 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.56 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.60 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.61 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.62 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 184.105.139.67 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.100 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.102 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.111 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.113 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.115 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.125 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.182 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.73 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.78 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 205.210.31.52 -j DROP  # scanner, 1 hits

# Repeat Offenders (>= 10 hits)
iptables -A INPUT -s 91.92.42.227 -j DROP  # 7764 hits
iptables -A INPUT -s 104.243.43.7 -j DROP  # 1018 hits
iptables -A INPUT -s 85.11.167.11 -j DROP  # 665 hits
iptables -A INPUT -s 175.149.183.33 -j DROP  # 323 hits
iptables -A INPUT -s 185.150.191.236 -j DROP  # 321 hits
iptables -A INPUT -s 45.198.224.18 -j DROP  # 162 hits
iptables -A INPUT -s 85.11.167.7 -j DROP  # 160 hits
iptables -A INPUT -s 176.65.139.41 -j DROP  # 154 hits
iptables -A INPUT -s 139.135.59.149 -j DROP  # 136 hits
iptables -A INPUT -s 188.166.223.76 -j DROP  # 136 hits
iptables -A INPUT -s 103.248.94.15 -j DROP  # 118 hits
iptables -A INPUT -s 104.243.35.104 -j DROP  # 118 hits
iptables -A INPUT -s 103.74.20.164 -j DROP  # 117 hits
iptables -A INPUT -s 223.123.38.125 -j DROP  # 117 hits
iptables -A INPUT -s 85.217.140.37 -j DROP  # 100 hits
iptables -A INPUT -s 66.228.43.62 -j DROP  # 78 hits
iptables -A INPUT -s 198.46.134.48 -j DROP  # 70 hits
iptables -A INPUT -s 104.243.35.94 -j DROP  # 69 hits
iptables -A INPUT -s 94.156.152.234 -j DROP  # 67 hits
iptables -A INPUT -s 45.205.1.5 -j DROP  # 62 hits
iptables -A INPUT -s 104.243.32.126 -j DROP  # 59 hits
iptables -A INPUT -s 104.243.35.120 -j DROP  # 59 hits
iptables -A INPUT -s 104.243.43.19 -j DROP  # 59 hits
iptables -A INPUT -s 85.217.140.5 -j DROP  # 41 hits
iptables -A INPUT -s 3.137.202.87 -j DROP  # 40 hits
iptables -A INPUT -s 134.209.49.207 -j DROP  # 39 hits
iptables -A INPUT -s 165.227.26.149 -j DROP  # 39 hits
iptables -A INPUT -s 45.79.207.223 -j DROP  # 39 hits
iptables -A INPUT -s 68.183.123.81 -j DROP  # 39 hits
iptables -A INPUT -s 93.123.72.166 -j DROP  # 32 hits
iptables -A INPUT -s 87.251.64.146 -j DROP  # 31 hits
iptables -A INPUT -s 120.85.115.7 -j DROP  # 30 hits
iptables -A INPUT -s 5.187.35.26 -j DROP  # 30 hits
iptables -A INPUT -s 85.217.140.43 -j DROP  # 30 hits
iptables -A INPUT -s 85.217.140.10 -j DROP  # 25 hits
iptables -A INPUT -s 85.217.140.22 -j DROP  # 23 hits
iptables -A INPUT -s 85.217.140.49 -j DROP  # 23 hits
iptables -A INPUT -s 85.217.140.32 -j DROP  # 22 hits
iptables -A INPUT -s 45.82.78.108 -j DROP  # 21 hits
iptables -A INPUT -s 93.123.72.183 -j DROP  # 20 hits
iptables -A INPUT -s 45.82.78.104 -j DROP  # 20 hits
iptables -A INPUT -s 18.226.235.136 -j DROP  # 19 hits
iptables -A INPUT -s 45.198.224.5 -j DROP  # 18 hits
iptables -A INPUT -s 120.27.153.162 -j DROP  # 18 hits
iptables -A INPUT -s 3.17.37.247 -j DROP  # 16 hits
iptables -A INPUT -s 45.82.78.100 -j DROP  # 16 hits
iptables -A INPUT -s 45.82.78.103 -j DROP  # 16 hits
iptables -A INPUT -s 45.82.78.107 -j DROP  # 16 hits
iptables -A INPUT -s 130.12.180.51 -j DROP  # 15 hits
iptables -A INPUT -s 18.218.180.187 -j DROP  # 15 hits
iptables -A INPUT -s 8.222.225.103 -j DROP  # 15 hits
iptables -A INPUT -s 204.76.203.206 -j DROP  # 14 hits
iptables -A INPUT -s 107.150.98.86 -j DROP  # 14 hits
iptables -A INPUT -s 45.142.154.112 -j DROP  # 14 hits
iptables -A INPUT -s 45.43.57.157 -j DROP  # 14 hits
iptables -A INPUT -s 78.128.113.46 -j DROP  # 14 hits
iptables -A INPUT -s 79.124.59.78 -j DROP  # 14 hits
iptables -A INPUT -s 204.76.203.219 -j DROP  # 13 hits
iptables -A INPUT -s 3.134.108.208 -j DROP  # 13 hits
iptables -A INPUT -s 151.243.11.35 -j DROP  # 12 hits
iptables -A INPUT -s 207.90.244.26 -j DROP  # 12 hits
iptables -A INPUT -s 3.142.236.166 -j DROP  # 12 hits
iptables -A INPUT -s 114.66.29.48 -j DROP  # 11 hits
iptables -A INPUT -s 176.65.139.103 -j DROP  # 11 hits
iptables -A INPUT -s 3.150.118.55 -j DROP  # 11 hits
iptables -A INPUT -s 45.135.193.193 -j DROP  # 11 hits
iptables -A INPUT -s 20.12.240.74 -j DROP  # 10 hits
iptables -A INPUT -s 3.140.245.171 -j DROP  # 10 hits
iptables -A INPUT -s 47.77.220.169 -j DROP  # 10 hits

# Active Attackers (>= 3 hits)
iptables -A INPUT -s 31.59.160.12 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.197.121 -j DROP  # 9 hits
iptables -A INPUT -s 18.222.214.46 -j DROP  # 9 hits
iptables -A INPUT -s 18.223.33.89 -j DROP  # 9 hits
iptables -A INPUT -s 192.253.248.180 -j DROP  # 9 hits
iptables -A INPUT -s 47.97.56.233 -j DROP  # 9 hits
iptables -A INPUT -s 51.159.110.167 -j DROP  # 9 hits
iptables -A INPUT -s 85.217.140.15 -j DROP  # 9 hits
iptables -A INPUT -s 86.54.31.34 -j DROP  # 9 hits
iptables -A INPUT -s 101.36.97.187 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.56.149 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.156.136 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.119.20 -j DROP  # 8 hits
iptables -A INPUT -s 18.222.30.185 -j DROP  # 8 hits
iptables -A INPUT -s 185.224.128.16 -j DROP  # 8 hits
iptables -A INPUT -s 195.178.110.204 -j DROP  # 8 hits
iptables -A INPUT -s 216.180.246.241 -j DROP  # 8 hits
iptables -A INPUT -s 44.220.185.59 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.102 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.106 -j DROP  # 8 hits
iptables -A INPUT -s 47.242.22.224 -j DROP  # 8 hits
iptables -A INPUT -s 78.128.112.6 -j DROP  # 8 hits
iptables -A INPUT -s 85.217.140.4 -j DROP  # 8 hits
iptables -A INPUT -s 91.191.209.98 -j DROP  # 8 hits
iptables -A INPUT -s 118.194.236.126 -j DROP  # 7 hits
iptables -A INPUT -s 123.58.207.155 -j DROP  # 7 hits
iptables -A INPUT -s 145.132.102.226 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.153.228 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.199.112 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.227.252 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.235.78 -j DROP  # 7 hits
iptables -A INPUT -s 164.138.221.184 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.12.82 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.128.199 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.33.72 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.26.61 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.5.118 -j DROP  # 7 hits
iptables -A INPUT -s 4.197.208.186 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.120 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.45 -j DROP  # 7 hits
iptables -A INPUT -s 8.211.138.198 -j DROP  # 7 hits
iptables -A INPUT -s 18.218.134.102 -j DROP  # 6 hits
iptables -A INPUT -s 117.33.242.50 -j DROP  # 6 hits
iptables -A INPUT -s 118.193.39.149 -j DROP  # 6 hits
iptables -A INPUT -s 165.154.172.194 -j DROP  # 6 hits
iptables -A INPUT -s 176.65.139.31 -j DROP  # 6 hits
iptables -A INPUT -s 185.242.226.73 -j DROP  # 6 hits
iptables -A INPUT -s 20.65.224.144 -j DROP  # 6 hits
iptables -A INPUT -s 207.90.244.12 -j DROP  # 6 hits
iptables -A INPUT -s 207.90.244.18 -j DROP  # 6 hits
iptables -A INPUT -s 45.205.1.76 -j DROP  # 6 hits
iptables -A INPUT -s 45.43.60.202 -j DROP  # 6 hits
iptables -A INPUT -s 47.251.248.226 -j DROP  # 6 hits
iptables -A INPUT -s 52.173.162.107 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.186.171 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.186.197 -j DROP  # 6 hits
iptables -A INPUT -s 78.128.112.30 -j DROP  # 6 hits
iptables -A INPUT -s 93.174.95.106 -j DROP  # 6 hits
iptables -A INPUT -s 45.205.1.245 -j DROP  # 5 hits
iptables -A INPUT -s 45.205.1.62 -j DROP  # 5 hits
iptables -A INPUT -s 110.36.26.164 -j DROP  # 5 hits
iptables -A INPUT -s 128.1.132.136 -j DROP  # 5 hits
iptables -A INPUT -s 13.59.79.101 -j DROP  # 5 hits
iptables -A INPUT -s 147.185.132.213 -j DROP  # 5 hits
iptables -A INPUT -s 147.185.132.60 -j DROP  # 5 hits
iptables -A INPUT -s 152.32.211.153 -j DROP  # 5 hits
iptables -A INPUT -s 18.219.240.216 -j DROP  # 5 hits
iptables -A INPUT -s 18.224.95.205 -j DROP  # 5 hits
iptables -A INPUT -s 183.81.169.76 -j DROP  # 5 hits
iptables -A INPUT -s 185.180.141.37 -j DROP  # 5 hits
iptables -A INPUT -s 37.49.182.216 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.185.10 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.188.242 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.13 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.38 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.42 -j DROP  # 5 hits
iptables -A INPUT -s 45.205.1.73 -j DROP  # 5 hits
iptables -A INPUT -s 47.251.122.165 -j DROP  # 5 hits
iptables -A INPUT -s 5.188.206.34 -j DROP  # 5 hits
iptables -A INPUT -s 60.191.137.103 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.195.57 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.195.61 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.195.80 -j DROP  # 5 hits
iptables -A INPUT -s 78.128.113.22 -j DROP  # 5 hits
iptables -A INPUT -s 8.216.16.200 -j DROP  # 5 hits
iptables -A INPUT -s 80.94.95.83 -j DROP  # 5 hits
iptables -A INPUT -s 91.230.168.248 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.17 -j DROP  # 4 hits
iptables -A INPUT -s 45.148.10.67 -j DROP  # 4 hits
iptables -A INPUT -s 45.205.1.241 -j DROP  # 4 hits
iptables -A INPUT -s 45.205.1.244 -j DROP  # 4 hits
iptables -A INPUT -s 103.153.68.209 -j DROP  # 4 hits
iptables -A INPUT -s 103.81.237.74 -j DROP  # 4 hits
iptables -A INPUT -s 104.168.28.15 -j DROP  # 4 hits
iptables -A INPUT -s 104.232.79.58 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.210.72 -j DROP  # 4 hits
iptables -A INPUT -s 109.123.251.5 -j DROP  # 4 hits
iptables -A INPUT -s 123.120.108.65 -j DROP  # 4 hits
iptables -A INPUT -s 124.43.79.34 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.144 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.240 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.63 -j DROP  # 4 hits
iptables -A INPUT -s 170.130.204.50 -j DROP  # 4 hits
iptables -A INPUT -s 18.191.80.47 -j DROP  # 4 hits
iptables -A INPUT -s 18.217.50.119 -j DROP  # 4 hits
iptables -A INPUT -s 18.218.206.145 -j DROP  # 4 hits
iptables -A INPUT -s 18.221.97.151 -j DROP  # 4 hits
iptables -A INPUT -s 18.222.159.244 -j DROP  # 4 hits
iptables -A INPUT -s 185.226.197.47 -j DROP  # 4 hits
iptables -A INPUT -s 204.76.203.81 -j DROP  # 4 hits
iptables -A INPUT -s 216.180.246.145 -j DROP  # 4 hits
iptables -A INPUT -s 216.180.246.207 -j DROP  # 4 hits
iptables -A INPUT -s 3.137.204.169 -j DROP  # 4 hits
iptables -A INPUT -s 3.139.64.14 -j DROP  # 4 hits
iptables -A INPUT -s 39.50.132.101 -j DROP  # 4 hits
iptables -A INPUT -s 45.205.1.240 -j DROP  # 4 hits
iptables -A INPUT -s 45.205.1.242 -j DROP  # 4 hits
iptables -A INPUT -s 45.205.1.246 -j DROP  # 4 hits
iptables -A INPUT -s 45.205.1.68 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.105 -j DROP  # 4 hits
iptables -A INPUT -s 45.91.64.6 -j DROP  # 4 hits
iptables -A INPUT -s 47.236.167.82 -j DROP  # 4 hits
iptables -A INPUT -s 47.250.180.183 -j DROP  # 4 hits
iptables -A INPUT -s 47.250.196.123 -j DROP  # 4 hits
iptables -A INPUT -s 47.251.127.247 -j DROP  # 4 hits
iptables -A INPUT -s 52.173.237.210 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.33 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.186.183 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.63 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.65 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.71 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.94 -j DROP  # 4 hits
iptables -A INPUT -s 78.128.113.74 -j DROP  # 4 hits
iptables -A INPUT -s 8.211.24.65 -j DROP  # 4 hits
iptables -A INPUT -s 8.216.4.184 -j DROP  # 4 hits
iptables -A INPUT -s 81.213.109.154 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.146 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.15 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.163 -j DROP  # 4 hits
iptables -A INPUT -s 91.231.89.71 -j DROP  # 4 hits
iptables -A INPUT -s 46.151.178.13 -j DROP  # 3 hits
iptables -A INPUT -s 103.195.31.156 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.73 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.75 -j DROP  # 3 hits
iptables -A INPUT -s 135.119.237.68 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.174 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.91 -j DROP  # 3 hits
iptables -A INPUT -s 150.107.36.236 -j DROP  # 3 hits
iptables -A INPUT -s 151.243.11.245 -j DROP  # 3 hits
iptables -A INPUT -s 151.243.11.248 -j DROP  # 3 hits
iptables -A INPUT -s 151.243.11.34 -j DROP  # 3 hits
iptables -A INPUT -s 165.154.11.247 -j DROP  # 3 hits
iptables -A INPUT -s 165.154.3.101 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.139.99 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.148.147 -j DROP  # 3 hits
iptables -A INPUT -s 185.180.141.38 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.197.48 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.104 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.17 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.87 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.118 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.169 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.172 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.64 -j DROP  # 3 hits
iptables -A INPUT -s 199.45.154.137 -j DROP  # 3 hits
iptables -A INPUT -s 199.45.155.101 -j DROP  # 3 hits
iptables -A INPUT -s 199.45.155.77 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.19 -j DROP  # 3 hits
iptables -A INPUT -s 209.222.101.194 -j DROP  # 3 hits
iptables -A INPUT -s 3.17.193.110 -j DROP  # 3 hits
iptables -A INPUT -s 3.18.101.245 -j DROP  # 3 hits
iptables -A INPUT -s 40.124.175.188 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.71 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.72 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.73 -j DROP  # 3 hits
iptables -A INPUT -s 47.237.121.158 -j DROP  # 3 hits
iptables -A INPUT -s 47.237.2.150 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.134.150 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.137.249 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.137.98 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.138.182 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.139.43 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.141.219 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.142.92 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.114.237 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.123.71 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.163.20 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.172.64 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.178.80 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.42.174 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.49.81 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.80.220 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.83.81 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.84.254 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.90.169 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.101.89 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.124.111 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.125.7 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.169.81 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.19.148 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.242.251 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.34.107 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.48.11 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.52.209 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.64.123 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.68.242 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.74.197 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.91.249 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.128.244 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.167.143 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.172.138 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.202.17 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.213.105 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.213.222 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.215.142 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.244.10 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.53.137 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.71.82 -j DROP  # 3 hits
iptables -A INPUT -s 47.74.26.96 -j DROP  # 3 hits
iptables -A INPUT -s 47.74.54.11 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.216.216 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.218.221 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.219.94 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.231.186 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.233.1 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.100.21 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.109.58 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.109.70 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.129.251 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.141.166 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.203.136 -j DROP  # 3 hits
iptables -A INPUT -s 47.88.104.94 -j DROP  # 3 hits
iptables -A INPUT -s 47.89.211.155 -j DROP  # 3 hits
iptables -A INPUT -s 47.89.247.91 -j DROP  # 3 hits
iptables -A INPUT -s 47.89.248.96 -j DROP  # 3 hits
iptables -A INPUT -s 47.89.251.210 -j DROP  # 3 hits
iptables -A INPUT -s 5.61.209.96 -j DROP  # 3 hits
iptables -A INPUT -s 59.125.215.94 -j DROP  # 3 hits
iptables -A INPUT -s 65.49.1.24 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.135 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.161 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.173 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.176 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.178 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.190 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.201 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.121 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.42 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.54 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.72 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.81 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.85 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.224.225 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.207.15 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.228.69 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.74.160 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.157.94 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.26.207 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.45.42 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.0.135 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.10.184 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.16.177 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.3.1 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.3.204 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.3.84 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.5.132 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.5.164 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.5.20 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.7.76 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.9.117 -j DROP  # 3 hits
iptables -A INPUT -s 85.217.140.52 -j DROP  # 3 hits
iptables -A INPUT -s 86.54.31.44 -j DROP  # 3 hits
iptables -A INPUT -s 91.191.209.118 -j DROP  # 3 hits
iptables -A INPUT -s 91.196.152.106 -j DROP  # 3 hits
iptables -A INPUT -s 91.196.152.209 -j DROP  # 3 hits
iptables -A INPUT -s 91.196.152.242 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.151 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.30 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.70 -j DROP  # 3 hits
iptables -A INPUT -s 91.231.89.241 -j DROP  # 3 hits