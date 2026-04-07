#!/bin/bash
# LLM Honeypot Intelligence - Firewall Blocklist
# Generated: 2026-04-07 15:36 UTC
# Total: 534 IPs | Blocked: 48 scanners + 122 repeat + 335 active

# Mass Scanners (known infrastructure)
iptables -A INPUT -s 167.94.146.52 -j DROP  # scanner, 20 hits
iptables -A INPUT -s 167.94.146.57 -j DROP  # scanner, 20 hits
iptables -A INPUT -s 167.94.146.53 -j DROP  # scanner, 19 hits
iptables -A INPUT -s 167.94.146.54 -j DROP  # scanner, 18 hits
iptables -A INPUT -s 167.94.146.59 -j DROP  # scanner, 18 hits
iptables -A INPUT -s 167.94.146.63 -j DROP  # scanner, 18 hits
iptables -A INPUT -s 167.94.146.51 -j DROP  # scanner, 16 hits
iptables -A INPUT -s 167.94.146.60 -j DROP  # scanner, 16 hits
iptables -A INPUT -s 167.94.146.49 -j DROP  # scanner, 12 hits
iptables -A INPUT -s 167.94.146.50 -j DROP  # scanner, 12 hits
iptables -A INPUT -s 167.94.146.62 -j DROP  # scanner, 12 hits
iptables -A INPUT -s 167.94.146.55 -j DROP  # scanner, 11 hits
iptables -A INPUT -s 167.94.146.56 -j DROP  # scanner, 11 hits
iptables -A INPUT -s 167.94.146.58 -j DROP  # scanner, 11 hits
iptables -A INPUT -s 167.94.146.61 -j DROP  # scanner, 11 hits
iptables -A INPUT -s 167.94.146.48 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 184.105.247.194 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 184.105.247.196 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 74.82.47.5 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 80.82.77.139 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 184.105.139.70 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 184.105.247.254 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 184.105.139.68 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 184.105.139.69 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 184.105.247.195 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.173 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.183 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.204 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.232 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.76 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.184 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.227 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 74.82.47.4 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 184.105.247.252 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.122 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.125 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.164 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.236 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.186 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.210 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.96 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 185.142.236.41 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.111 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.174 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.57 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 205.210.31.178 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 205.210.31.200 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 205.210.31.79 -j DROP  # scanner, 1 hits

# Repeat Offenders (>= 10 hits)
iptables -A INPUT -s 187.108.1.130 -j DROP  # 5800 hits
iptables -A INPUT -s 85.11.167.11 -j DROP  # 1274 hits
iptables -A INPUT -s 157.230.235.42 -j DROP  # 1260 hits
iptables -A INPUT -s 165.245.172.231 -j DROP  # 745 hits
iptables -A INPUT -s 85.217.140.45 -j DROP  # 431 hits
iptables -A INPUT -s 185.91.127.85 -j DROP  # 288 hits
iptables -A INPUT -s 85.217.140.13 -j DROP  # 281 hits
iptables -A INPUT -s 85.217.140.37 -j DROP  # 258 hits
iptables -A INPUT -s 45.205.1.110 -j DROP  # 244 hits
iptables -A INPUT -s 85.217.140.41 -j DROP  # 221 hits
iptables -A INPUT -s 85.217.140.40 -j DROP  # 210 hits
iptables -A INPUT -s 85.217.140.43 -j DROP  # 195 hits
iptables -A INPUT -s 45.205.1.5 -j DROP  # 179 hits
iptables -A INPUT -s 85.217.140.49 -j DROP  # 159 hits
iptables -A INPUT -s 85.217.140.52 -j DROP  # 148 hits
iptables -A INPUT -s 85.217.140.29 -j DROP  # 144 hits
iptables -A INPUT -s 18.218.118.203 -j DROP  # 137 hits
iptables -A INPUT -s 16.58.56.214 -j DROP  # 134 hits
iptables -A INPUT -s 85.217.140.48 -j DROP  # 130 hits
iptables -A INPUT -s 18.116.101.220 -j DROP  # 124 hits
iptables -A INPUT -s 85.217.140.7 -j DROP  # 122 hits
iptables -A INPUT -s 85.217.140.42 -j DROP  # 120 hits
iptables -A INPUT -s 85.217.140.46 -j DROP  # 120 hits
iptables -A INPUT -s 85.217.140.39 -j DROP  # 118 hits
iptables -A INPUT -s 85.217.140.9 -j DROP  # 116 hits
iptables -A INPUT -s 3.132.26.232 -j DROP  # 115 hits
iptables -A INPUT -s 3.131.220.121 -j DROP  # 112 hits
iptables -A INPUT -s 85.217.140.23 -j DROP  # 109 hits
iptables -A INPUT -s 3.130.168.2 -j DROP  # 105 hits
iptables -A INPUT -s 3.129.187.38 -j DROP  # 78 hits
iptables -A INPUT -s 85.217.140.2 -j DROP  # 78 hits
iptables -A INPUT -s 165.245.163.7 -j DROP  # 75 hits
iptables -A INPUT -s 85.217.140.10 -j DROP  # 75 hits
iptables -A INPUT -s 85.217.140.50 -j DROP  # 72 hits
iptables -A INPUT -s 34.62.39.11 -j DROP  # 71 hits
iptables -A INPUT -s 34.77.105.211 -j DROP  # 71 hits
iptables -A INPUT -s 35.195.163.229 -j DROP  # 71 hits
iptables -A INPUT -s 35.233.96.247 -j DROP  # 71 hits
iptables -A INPUT -s 85.217.140.16 -j DROP  # 71 hits
iptables -A INPUT -s 80.66.83.80 -j DROP  # 69 hits
iptables -A INPUT -s 81.29.142.100 -j DROP  # 69 hits
iptables -A INPUT -s 91.224.92.125 -j DROP  # 64 hits
iptables -A INPUT -s 92.110.87.38 -j DROP  # 63 hits
iptables -A INPUT -s 85.217.140.44 -j DROP  # 57 hits
iptables -A INPUT -s 92.118.39.30 -j DROP  # 56 hits
iptables -A INPUT -s 85.217.140.8 -j DROP  # 55 hits
iptables -A INPUT -s 85.217.140.51 -j DROP  # 54 hits
iptables -A INPUT -s 176.65.139.105 -j DROP  # 53 hits
iptables -A INPUT -s 85.11.167.2 -j DROP  # 52 hits
iptables -A INPUT -s 46.151.178.13 -j DROP  # 51 hits
iptables -A INPUT -s 123.4.226.11 -j DROP  # 50 hits
iptables -A INPUT -s 139.135.40.201 -j DROP  # 50 hits
iptables -A INPUT -s 182.119.63.172 -j DROP  # 50 hits
iptables -A INPUT -s 85.217.140.19 -j DROP  # 50 hits
iptables -A INPUT -s 45.205.1.26 -j DROP  # 48 hits
iptables -A INPUT -s 110.37.28.119 -j DROP  # 46 hits
iptables -A INPUT -s 3.134.216.108 -j DROP  # 44 hits
iptables -A INPUT -s 92.63.197.22 -j DROP  # 40 hits
iptables -A INPUT -s 198.58.122.200 -j DROP  # 39 hits
iptables -A INPUT -s 81.29.142.6 -j DROP  # 39 hits
iptables -A INPUT -s 204.76.203.206 -j DROP  # 36 hits
iptables -A INPUT -s 45.82.78.108 -j DROP  # 36 hits
iptables -A INPUT -s 85.217.140.38 -j DROP  # 36 hits
iptables -A INPUT -s 138.197.138.15 -j DROP  # 35 hits
iptables -A INPUT -s 85.217.140.32 -j DROP  # 35 hits
iptables -A INPUT -s 85.217.140.36 -j DROP  # 32 hits
iptables -A INPUT -s 94.243.12.44 -j DROP  # 30 hits
iptables -A INPUT -s 141.98.10.164 -j DROP  # 28 hits
iptables -A INPUT -s 170.39.218.48 -j DROP  # 26 hits
iptables -A INPUT -s 85.217.140.33 -j DROP  # 26 hits
iptables -A INPUT -s 128.199.225.7 -j DROP  # 25 hits
iptables -A INPUT -s 221.11.172.25 -j DROP  # 25 hits
iptables -A INPUT -s 223.123.72.142 -j DROP  # 25 hits
iptables -A INPUT -s 79.124.59.78 -j DROP  # 25 hits
iptables -A INPUT -s 45.82.78.102 -j DROP  # 24 hits
iptables -A INPUT -s 45.82.78.106 -j DROP  # 24 hits
iptables -A INPUT -s 45.82.78.100 -j DROP  # 23 hits
iptables -A INPUT -s 170.39.218.251 -j DROP  # 22 hits
iptables -A INPUT -s 186.54.80.206 -j DROP  # 22 hits
iptables -A INPUT -s 51.158.205.203 -j DROP  # 22 hits
iptables -A INPUT -s 113.44.245.69 -j DROP  # 21 hits
iptables -A INPUT -s 138.68.82.46 -j DROP  # 21 hits
iptables -A INPUT -s 45.153.34.204 -j DROP  # 21 hits
iptables -A INPUT -s 170.39.218.32 -j DROP  # 20 hits
iptables -A INPUT -s 45.82.78.105 -j DROP  # 20 hits
iptables -A INPUT -s 45.82.78.107 -j DROP  # 20 hits
iptables -A INPUT -s 85.217.140.27 -j DROP  # 20 hits
iptables -A INPUT -s 87.251.64.141 -j DROP  # 20 hits
iptables -A INPUT -s 185.236.25.175 -j DROP  # 19 hits
iptables -A INPUT -s 85.217.140.12 -j DROP  # 19 hits
iptables -A INPUT -s 31.14.32.8 -j DROP  # 18 hits
iptables -A INPUT -s 176.65.139.81 -j DROP  # 16 hits
iptables -A INPUT -s 152.32.250.36 -j DROP  # 15 hits
iptables -A INPUT -s 31.14.32.5 -j DROP  # 15 hits
iptables -A INPUT -s 95.214.52.233 -j DROP  # 15 hits
iptables -A INPUT -s 159.89.8.35 -j DROP  # 14 hits
iptables -A INPUT -s 193.142.146.230 -j DROP  # 14 hits
iptables -A INPUT -s 45.142.154.93 -j DROP  # 14 hits
iptables -A INPUT -s 93.123.109.183 -j DROP  # 14 hits
iptables -A INPUT -s 124.198.131.185 -j DROP  # 13 hits
iptables -A INPUT -s 193.29.13.39 -j DROP  # 13 hits
iptables -A INPUT -s 45.142.154.107 -j DROP  # 13 hits
iptables -A INPUT -s 139.59.4.64 -j DROP  # 12 hits
iptables -A INPUT -s 204.76.203.56 -j DROP  # 12 hits
iptables -A INPUT -s 206.135.174.60 -j DROP  # 12 hits
iptables -A INPUT -s 207.90.244.17 -j DROP  # 12 hits
iptables -A INPUT -s 207.90.244.18 -j DROP  # 12 hits
iptables -A INPUT -s 207.90.244.19 -j DROP  # 12 hits
iptables -A INPUT -s 45.148.10.121 -j DROP  # 12 hits
iptables -A INPUT -s 45.82.78.103 -j DROP  # 12 hits
iptables -A INPUT -s 45.82.78.104 -j DROP  # 12 hits
iptables -A INPUT -s 66.228.42.204 -j DROP  # 12 hits
iptables -A INPUT -s 130.12.180.51 -j DROP  # 11 hits
iptables -A INPUT -s 138.197.24.249 -j DROP  # 11 hits
iptables -A INPUT -s 170.64.177.80 -j DROP  # 11 hits
iptables -A INPUT -s 204.76.203.215 -j DROP  # 11 hits
iptables -A INPUT -s 3.151.241.153 -j DROP  # 11 hits
iptables -A INPUT -s 103.247.61.20 -j DROP  # 10 hits
iptables -A INPUT -s 152.32.176.68 -j DROP  # 10 hits
iptables -A INPUT -s 185.226.197.32 -j DROP  # 10 hits
iptables -A INPUT -s 45.156.128.61 -j DROP  # 10 hits
iptables -A INPUT -s 80.66.83.43 -j DROP  # 10 hits

# Active Attackers (>= 3 hits)
iptables -A INPUT -s 101.36.107.65 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.159.97 -j DROP  # 9 hits
iptables -A INPUT -s 178.83.200.2 -j DROP  # 9 hits
iptables -A INPUT -s 18.97.5.83 -j DROP  # 9 hits
iptables -A INPUT -s 185.242.226.71 -j DROP  # 9 hits
iptables -A INPUT -s 185.242.226.9 -j DROP  # 9 hits
iptables -A INPUT -s 195.178.110.204 -j DROP  # 9 hits
iptables -A INPUT -s 207.90.244.26 -j DROP  # 9 hits
iptables -A INPUT -s 207.90.244.4 -j DROP  # 9 hits
iptables -A INPUT -s 207.90.244.6 -j DROP  # 9 hits
iptables -A INPUT -s 44.220.185.144 -j DROP  # 9 hits
iptables -A INPUT -s 64.62.197.122 -j DROP  # 9 hits
iptables -A INPUT -s 85.217.140.17 -j DROP  # 9 hits
iptables -A INPUT -s 101.36.97.70 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.35.202 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.40.191 -j DROP  # 8 hits
iptables -A INPUT -s 128.14.239.39 -j DROP  # 8 hits
iptables -A INPUT -s 150.107.38.5 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.185.141 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.202.244 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.208.106 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.250.21 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.11.210 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.164.112 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.164.114 -j DROP  # 8 hits
iptables -A INPUT -s 185.224.128.16 -j DROP  # 8 hits
iptables -A INPUT -s 185.242.226.10 -j DROP  # 8 hits
iptables -A INPUT -s 44.220.188.95 -j DROP  # 8 hits
iptables -A INPUT -s 51.159.110.167 -j DROP  # 8 hits
iptables -A INPUT -s 64.62.156.38 -j DROP  # 8 hits
iptables -A INPUT -s 85.217.140.35 -j DROP  # 8 hits
iptables -A INPUT -s 65.49.1.108 -j DROP  # 7 hits
iptables -A INPUT -s 103.203.58.4 -j DROP  # 7 hits
iptables -A INPUT -s 147.185.132.93 -j DROP  # 7 hits
iptables -A INPUT -s 161.35.195.40 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.129.74 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.163.10 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.209 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.237 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.114 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.174 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.21 -j DROP  # 7 hits
iptables -A INPUT -s 45.156.128.51 -j DROP  # 7 hits
iptables -A INPUT -s 64.62.197.92 -j DROP  # 7 hits
iptables -A INPUT -s 85.217.140.6 -j DROP  # 7 hits
iptables -A INPUT -s 98.80.4.6 -j DROP  # 7 hits
iptables -A INPUT -s 98.80.4.65 -j DROP  # 7 hits
iptables -A INPUT -s 109.105.209.7 -j DROP  # 6 hits
iptables -A INPUT -s 121.199.37.113 -j DROP  # 6 hits
iptables -A INPUT -s 130.12.180.174 -j DROP  # 6 hits
iptables -A INPUT -s 152.32.133.174 -j DROP  # 6 hits
iptables -A INPUT -s 176.120.22.135 -j DROP  # 6 hits
iptables -A INPUT -s 185.180.141.7 -j DROP  # 6 hits
iptables -A INPUT -s 185.226.197.34 -j DROP  # 6 hits
iptables -A INPUT -s 185.93.89.190 -j DROP  # 6 hits
iptables -A INPUT -s 185.93.89.193 -j DROP  # 6 hits
iptables -A INPUT -s 207.90.244.12 -j DROP  # 6 hits
iptables -A INPUT -s 211.154.155.17 -j DROP  # 6 hits
iptables -A INPUT -s 3.143.162.210 -j DROP  # 6 hits
iptables -A INPUT -s 45.142.154.32 -j DROP  # 6 hits
iptables -A INPUT -s 45.142.154.35 -j DROP  # 6 hits
iptables -A INPUT -s 47.245.138.144 -j DROP  # 6 hits
iptables -A INPUT -s 47.250.95.159 -j DROP  # 6 hits
iptables -A INPUT -s 47.251.68.60 -j DROP  # 6 hits
iptables -A INPUT -s 47.84.116.144 -j DROP  # 6 hits
iptables -A INPUT -s 47.84.138.72 -j DROP  # 6 hits
iptables -A INPUT -s 58.251.255.86 -j DROP  # 6 hits
iptables -A INPUT -s 64.62.197.182 -j DROP  # 6 hits
iptables -A INPUT -s 65.49.1.212 -j DROP  # 6 hits
iptables -A INPUT -s 65.49.1.24 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.172.199 -j DROP  # 6 hits
iptables -A INPUT -s 81.56.32.71 -j DROP  # 6 hits
iptables -A INPUT -s 85.217.140.28 -j DROP  # 6 hits
iptables -A INPUT -s 94.102.49.155 -j DROP  # 6 hits
iptables -A INPUT -s 95.215.0.144 -j DROP  # 6 hits
iptables -A INPUT -s 103.218.243.246 -j DROP  # 5 hits
iptables -A INPUT -s 106.75.11.100 -j DROP  # 5 hits
iptables -A INPUT -s 106.75.13.39 -j DROP  # 5 hits
iptables -A INPUT -s 109.105.210.57 -j DROP  # 5 hits
iptables -A INPUT -s 109.105.210.67 -j DROP  # 5 hits
iptables -A INPUT -s 141.98.10.108 -j DROP  # 5 hits
iptables -A INPUT -s 18.97.19.240 -j DROP  # 5 hits
iptables -A INPUT -s 185.226.197.37 -j DROP  # 5 hits
iptables -A INPUT -s 185.93.89.191 -j DROP  # 5 hits
iptables -A INPUT -s 204.76.203.18 -j DROP  # 5 hits
iptables -A INPUT -s 38.250.187.139 -j DROP  # 5 hits
iptables -A INPUT -s 40.124.175.26 -j DROP  # 5 hits
iptables -A INPUT -s 43.106.131.75 -j DROP  # 5 hits
iptables -A INPUT -s 43.106.135.193 -j DROP  # 5 hits
iptables -A INPUT -s 43.106.135.98 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.188.75 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.105 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.110 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.33 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.41 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.129.75 -j DROP  # 5 hits
iptables -A INPUT -s 5.61.209.107 -j DROP  # 5 hits
iptables -A INPUT -s 64.62.156.122 -j DROP  # 5 hits
iptables -A INPUT -s 65.49.1.132 -j DROP  # 5 hits
iptables -A INPUT -s 65.49.1.222 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.186.172 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.186.177 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.195.32 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.195.45 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.195.72 -j DROP  # 5 hits
iptables -A INPUT -s 8.211.30.73 -j DROP  # 5 hits
iptables -A INPUT -s 86.54.31.42 -j DROP  # 5 hits
iptables -A INPUT -s 91.230.168.248 -j DROP  # 5 hits
iptables -A INPUT -s 98.89.204.118 -j DROP  # 5 hits
iptables -A INPUT -s 118.193.33.249 -j DROP  # 4 hits
iptables -A INPUT -s 176.65.149.227 -j DROP  # 4 hits
iptables -A INPUT -s 31.57.216.224 -j DROP  # 4 hits
iptables -A INPUT -s 65.49.1.122 -j DROP  # 4 hits
iptables -A INPUT -s 65.49.1.162 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.209.28 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.210.72 -j DROP  # 4 hits
iptables -A INPUT -s 143.198.122.35 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.177 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.27 -j DROP  # 4 hits
iptables -A INPUT -s 185.180.141.32 -j DROP  # 4 hits
iptables -A INPUT -s 185.180.141.35 -j DROP  # 4 hits
iptables -A INPUT -s 185.226.197.35 -j DROP  # 4 hits
iptables -A INPUT -s 20.169.104.211 -j DROP  # 4 hits
iptables -A INPUT -s 20.83.32.170 -j DROP  # 4 hits
iptables -A INPUT -s 222.186.13.130 -j DROP  # 4 hits
iptables -A INPUT -s 34.193.119.44 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.128.76 -j DROP  # 4 hits
iptables -A INPUT -s 45.205.1.23 -j DROP  # 4 hits
iptables -A INPUT -s 45.33.5.31 -j DROP  # 4 hits
iptables -A INPUT -s 45.79.181.251 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.156.182 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.156.66 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.156.80 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.197.107 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.197.152 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.197.167 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.197.2 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.197.77 -j DROP  # 4 hits
iptables -A INPUT -s 65.49.1.142 -j DROP  # 4 hits
iptables -A INPUT -s 65.49.1.38 -j DROP  # 4 hits
iptables -A INPUT -s 65.49.20.67 -j DROP  # 4 hits
iptables -A INPUT -s 65.49.20.69 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.107 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.111 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.179 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.208 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.35 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.41 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.98 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.89 -j DROP  # 4 hits
iptables -A INPUT -s 8.216.2.109 -j DROP  # 4 hits
iptables -A INPUT -s 84.233.216.142 -j DROP  # 4 hits
iptables -A INPUT -s 85.217.140.25 -j DROP  # 4 hits
iptables -A INPUT -s 85.217.140.31 -j DROP  # 4 hits
iptables -A INPUT -s 85.217.140.47 -j DROP  # 4 hits
iptables -A INPUT -s 91.196.152.21 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.1 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.183 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.213 -j DROP  # 4 hits
iptables -A INPUT -s 91.231.89.54 -j DROP  # 4 hits
iptables -A INPUT -s 91.231.89.86 -j DROP  # 4 hits
iptables -A INPUT -s 93.174.95.106 -j DROP  # 4 hits
iptables -A INPUT -s 94.231.206.109 -j DROP  # 4 hits
iptables -A INPUT -s 158.220.112.143 -j DROP  # 3 hits
iptables -A INPUT -s 34.78.28.28 -j DROP  # 3 hits
iptables -A INPUT -s 100.28.191.174 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.209.27 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.209.30 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.59 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.68 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.73 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.74 -j DROP  # 3 hits
iptables -A INPUT -s 13.219.1.233 -j DROP  # 3 hits
iptables -A INPUT -s 13.86.116.159 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.170 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.37 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.40 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.97 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.120 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.152 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.51 -j DROP  # 3 hits
iptables -A INPUT -s 152.32.134.89 -j DROP  # 3 hits
iptables -A INPUT -s 152.32.148.140 -j DROP  # 3 hits
iptables -A INPUT -s 152.32.148.250 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.117 -j DROP  # 3 hits
iptables -A INPUT -s 165.154.173.226 -j DROP  # 3 hits
iptables -A INPUT -s 165.154.206.71 -j DROP  # 3 hits
iptables -A INPUT -s 167.99.109.156 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.132.107 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.134.34 -j DROP  # 3 hits
iptables -A INPUT -s 185.180.141.10 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.197.33 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.197.38 -j DROP  # 3 hits
iptables -A INPUT -s 185.247.95.154 -j DROP  # 3 hits
iptables -A INPUT -s 185.93.89.192 -j DROP  # 3 hits
iptables -A INPUT -s 192.109.200.204 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.127 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.3 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.5 -j DROP  # 3 hits
iptables -A INPUT -s 20.221.69.50 -j DROP  # 3 hits
iptables -A INPUT -s 20.64.105.236 -j DROP  # 3 hits
iptables -A INPUT -s 216.218.206.66 -j DROP  # 3 hits
iptables -A INPUT -s 216.218.206.67 -j DROP  # 3 hits
iptables -A INPUT -s 216.218.206.69 -j DROP  # 3 hits
iptables -A INPUT -s 34.230.221.101 -j DROP  # 3 hits
iptables -A INPUT -s 35.203.210.237 -j DROP  # 3 hits
iptables -A INPUT -s 35.203.211.191 -j DROP  # 3 hits
iptables -A INPUT -s 41.110.4.106 -j DROP  # 3 hits
iptables -A INPUT -s 43.106.144.158 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.63 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.64 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.77 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.129.76 -j DROP  # 3 hits
iptables -A INPUT -s 45.33.14.5 -j DROP  # 3 hits
iptables -A INPUT -s 45.91.64.7 -j DROP  # 3 hits
iptables -A INPUT -s 47.236.178.25 -j DROP  # 3 hits
iptables -A INPUT -s 47.236.198.105 -j DROP  # 3 hits
iptables -A INPUT -s 47.236.201.172 -j DROP  # 3 hits
iptables -A INPUT -s 47.236.252.83 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.10.23 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.105.222 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.130.67 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.135.94 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.136.243 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.137.16 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.137.228 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.138.1 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.139.101 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.140.111 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.141.153 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.142.46 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.143.5 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.11.146 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.119.51 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.120.163 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.128.13 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.129.126 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.137.24 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.146.29 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.147.77 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.150.150 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.151.109 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.160.227 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.175.33 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.178.89 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.37.13 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.57.127 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.85.210 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.85.86 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.86.46 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.87.56 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.92.199 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.94.97 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.95.54 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.100.123 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.105.187 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.105.241 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.105.28 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.111.209 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.116.218 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.127.247 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.141.186 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.141.39 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.168.192 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.170.101 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.174.68 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.184.247 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.190.194 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.191.44 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.20.113 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.244.143 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.248.226 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.249.232 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.249.71 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.249.8 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.251.225 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.27.189 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.35.109 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.37.0 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.46.185 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.48.155 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.50.227 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.50.33 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.7.228 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.81.121 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.90.30 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.93.184 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.96.168 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.134.220 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.144.111 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.150.91 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.156.46 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.158.193 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.179.178 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.184.178 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.197.224 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.199.36 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.20.18 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.200.51 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.206.163 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.231.20 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.234.201 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.240.14 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.243.99 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.36.99 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.50.53 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.72.52 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.84.227 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.84.236 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.93.174 -j DROP  # 3 hits
iptables -A INPUT -s 47.74.27.55 -j DROP  # 3 hits
iptables -A INPUT -s 47.74.4.253 -j DROP  # 3 hits
iptables -A INPUT -s 47.74.63.6 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.192.57 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.195.68 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.213.24 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.213.54 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.218.87 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.219.25 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.228.132 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.231.186 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.233.21 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.233.248 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.101.166 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.105.75 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.106.82 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.109.110 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.109.59 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.110.132 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.117.21 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.130.19 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.134.69 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.135.131 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.138.189 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.138.233 -j DROP  # 3 hits