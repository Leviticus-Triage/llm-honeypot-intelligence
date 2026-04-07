#!/bin/bash
# LLM Honeypot Intelligence - Firewall Blocklist
# Generated: 2026-04-07 03:36 UTC
# Total: 507 IPs | Blocked: 57 scanners + 49 repeat + 146 active

# Mass Scanners (known infrastructure)
iptables -A INPUT -s 167.94.146.53 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 167.94.146.57 -j DROP  # scanner, 9 hits
iptables -A INPUT -s 167.94.146.63 -j DROP  # scanner, 9 hits
iptables -A INPUT -s 167.94.146.51 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.52 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.59 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.60 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.49 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 167.94.146.50 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 167.94.146.61 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 167.94.146.58 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.232 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.227 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 167.94.146.48 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.54 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.62 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.122 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.164 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.96 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 66.240.192.138 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 74.82.47.4 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.55 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.11 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.115 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.129 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.131 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.145 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.155 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.183 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.199 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.200 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.204 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.236 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.30 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.48 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.76 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.91 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.94 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.135 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.15 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.174 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.182 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.184 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.186 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.196 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.198 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.23 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.253 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.50 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.59 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.78 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.99 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 80.82.77.139 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 185.142.236.41 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.111 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.57 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 205.210.31.178 -j DROP  # scanner, 1 hits

# Repeat Offenders (>= 10 hits)
iptables -A INPUT -s 157.230.235.42 -j DROP  # 1260 hits
iptables -A INPUT -s 165.245.172.231 -j DROP  # 745 hits
iptables -A INPUT -s 85.11.167.11 -j DROP  # 509 hits
iptables -A INPUT -s 185.91.127.85 -j DROP  # 162 hits
iptables -A INPUT -s 45.205.1.110 -j DROP  # 98 hits
iptables -A INPUT -s 165.245.163.7 -j DROP  # 75 hits
iptables -A INPUT -s 45.205.1.5 -j DROP  # 63 hits
iptables -A INPUT -s 92.110.87.38 -j DROP  # 63 hits
iptables -A INPUT -s 139.135.40.201 -j DROP  # 50 hits
iptables -A INPUT -s 182.119.63.172 -j DROP  # 50 hits
iptables -A INPUT -s 85.217.140.41 -j DROP  # 37 hits
iptables -A INPUT -s 81.29.142.100 -j DROP  # 35 hits
iptables -A INPUT -s 85.217.140.50 -j DROP  # 35 hits
iptables -A INPUT -s 85.217.140.44 -j DROP  # 34 hits
iptables -A INPUT -s 85.217.140.40 -j DROP  # 32 hits
iptables -A INPUT -s 85.217.140.7 -j DROP  # 31 hits
iptables -A INPUT -s 81.29.142.6 -j DROP  # 30 hits
iptables -A INPUT -s 85.217.140.23 -j DROP  # 24 hits
iptables -A INPUT -s 85.217.140.52 -j DROP  # 24 hits
iptables -A INPUT -s 85.11.167.2 -j DROP  # 22 hits
iptables -A INPUT -s 85.217.140.38 -j DROP  # 22 hits
iptables -A INPUT -s 45.205.1.26 -j DROP  # 21 hits
iptables -A INPUT -s 85.217.140.51 -j DROP  # 21 hits
iptables -A INPUT -s 176.65.139.105 -j DROP  # 20 hits
iptables -A INPUT -s 85.217.140.27 -j DROP  # 20 hits
iptables -A INPUT -s 92.118.39.30 -j DROP  # 20 hits
iptables -A INPUT -s 185.236.25.175 -j DROP  # 19 hits
iptables -A INPUT -s 3.130.168.2 -j DROP  # 18 hits
iptables -A INPUT -s 91.224.92.125 -j DROP  # 16 hits
iptables -A INPUT -s 46.151.178.13 -j DROP  # 15 hits
iptables -A INPUT -s 16.58.56.214 -j DROP  # 15 hits
iptables -A INPUT -s 18.116.101.220 -j DROP  # 15 hits
iptables -A INPUT -s 85.217.140.32 -j DROP  # 15 hits
iptables -A INPUT -s 141.98.10.164 -j DROP  # 14 hits
iptables -A INPUT -s 45.142.154.93 -j DROP  # 14 hits
iptables -A INPUT -s 92.63.197.22 -j DROP  # 14 hits
iptables -A INPUT -s 93.123.109.183 -j DROP  # 14 hits
iptables -A INPUT -s 204.76.203.206 -j DROP  # 13 hits
iptables -A INPUT -s 85.217.140.8 -j DROP  # 13 hits
iptables -A INPUT -s 85.217.140.9 -j DROP  # 13 hits
iptables -A INPUT -s 159.89.8.35 -j DROP  # 12 hits
iptables -A INPUT -s 3.129.187.38 -j DROP  # 12 hits
iptables -A INPUT -s 66.228.42.204 -j DROP  # 12 hits
iptables -A INPUT -s 85.217.140.43 -j DROP  # 12 hits
iptables -A INPUT -s 138.197.24.249 -j DROP  # 11 hits
iptables -A INPUT -s 31.14.32.8 -j DROP  # 11 hits
iptables -A INPUT -s 45.82.78.100 -j DROP  # 11 hits
iptables -A INPUT -s 185.226.197.32 -j DROP  # 10 hits
iptables -A INPUT -s 79.124.59.78 -j DROP  # 10 hits

# Active Attackers (>= 3 hits)
iptables -A INPUT -s 170.39.218.48 -j DROP  # 9 hits
iptables -A INPUT -s 207.90.244.19 -j DROP  # 9 hits
iptables -A INPUT -s 85.217.140.36 -j DROP  # 9 hits
iptables -A INPUT -s 101.36.97.70 -j DROP  # 8 hits
iptables -A INPUT -s 150.107.38.5 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.208.106 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.11.210 -j DROP  # 8 hits
iptables -A INPUT -s 170.39.218.251 -j DROP  # 8 hits
iptables -A INPUT -s 44.220.188.95 -j DROP  # 8 hits
iptables -A INPUT -s 85.217.140.35 -j DROP  # 8 hits
iptables -A INPUT -s 103.203.58.4 -j DROP  # 7 hits
iptables -A INPUT -s 138.68.82.46 -j DROP  # 7 hits
iptables -A INPUT -s 161.35.195.40 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.114 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.174 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.21 -j DROP  # 7 hits
iptables -A INPUT -s 45.156.128.51 -j DROP  # 7 hits
iptables -A INPUT -s 85.217.140.6 -j DROP  # 7 hits
iptables -A INPUT -s 98.80.4.6 -j DROP  # 7 hits
iptables -A INPUT -s 109.105.209.7 -j DROP  # 6 hits
iptables -A INPUT -s 152.32.133.174 -j DROP  # 6 hits
iptables -A INPUT -s 170.39.218.32 -j DROP  # 6 hits
iptables -A INPUT -s 185.180.141.7 -j DROP  # 6 hits
iptables -A INPUT -s 185.226.197.34 -j DROP  # 6 hits
iptables -A INPUT -s 211.154.155.17 -j DROP  # 6 hits
iptables -A INPUT -s 3.131.220.121 -j DROP  # 6 hits
iptables -A INPUT -s 45.148.10.121 -j DROP  # 6 hits
iptables -A INPUT -s 47.245.138.144 -j DROP  # 6 hits
iptables -A INPUT -s 93.174.95.106 -j DROP  # 6 hits
iptables -A INPUT -s 94.102.49.155 -j DROP  # 6 hits
iptables -A INPUT -s 103.218.243.246 -j DROP  # 5 hits
iptables -A INPUT -s 109.105.210.57 -j DROP  # 5 hits
iptables -A INPUT -s 109.105.210.67 -j DROP  # 5 hits
iptables -A INPUT -s 147.185.132.93 -j DROP  # 5 hits
iptables -A INPUT -s 18.97.19.240 -j DROP  # 5 hits
iptables -A INPUT -s 204.76.203.56 -j DROP  # 5 hits
iptables -A INPUT -s 43.106.131.75 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.188.75 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.129.75 -j DROP  # 5 hits
iptables -A INPUT -s 65.49.1.132 -j DROP  # 5 hits
iptables -A INPUT -s 8.211.30.73 -j DROP  # 5 hits
iptables -A INPUT -s 86.54.31.42 -j DROP  # 5 hits
iptables -A INPUT -s 95.214.52.233 -j DROP  # 5 hits
iptables -A INPUT -s 118.193.33.249 -j DROP  # 4 hits
iptables -A INPUT -s 130.12.180.174 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.177 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.27 -j DROP  # 4 hits
iptables -A INPUT -s 185.226.197.35 -j DROP  # 4 hits
iptables -A INPUT -s 204.76.203.215 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.128.61 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.128.76 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.102 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.104 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.105 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.107 -j DROP  # 4 hits
iptables -A INPUT -s 65.49.1.212 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.98 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.32 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.210.59 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.68 -j DROP  # 3 hits
iptables -A INPUT -s 124.198.131.185 -j DROP  # 3 hits
iptables -A INPUT -s 13.86.116.159 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.204 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.54 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.51 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.150.72 -j DROP  # 3 hits
iptables -A INPUT -s 185.180.141.10 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.197.33 -j DROP  # 3 hits
iptables -A INPUT -s 192.109.200.204 -j DROP  # 3 hits
iptables -A INPUT -s 193.142.146.230 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.17 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.18 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.26 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.63 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.64 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.77 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.129.76 -j DROP  # 3 hits
iptables -A INPUT -s 47.236.178.25 -j DROP  # 3 hits
iptables -A INPUT -s 47.236.198.105 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.10.23 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.130.67 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.136.243 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.137.228 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.141.153 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.129.126 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.160.227 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.175.33 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.85.86 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.92.199 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.95.159 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.95.54 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.111.209 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.168.192 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.170.101 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.184.247 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.190.194 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.191.44 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.244.143 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.249.232 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.251.225 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.50.227 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.81.121 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.90.30 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.96.168 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.150.91 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.158.193 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.179.178 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.240.14 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.36.99 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.84.236 -j DROP  # 3 hits
iptables -A INPUT -s 47.74.4.253 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.213.54 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.218.87 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.233.248 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.105.75 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.116.144 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.117.21 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.130.19 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.138.233 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.138.72 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.139.148 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.139.182 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.139.203 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.200.194 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.207.3 -j DROP  # 3 hits
iptables -A INPUT -s 47.88.55.214 -j DROP  # 3 hits
iptables -A INPUT -s 47.89.209.143 -j DROP  # 3 hits
iptables -A INPUT -s 47.91.72.158 -j DROP  # 3 hits
iptables -A INPUT -s 47.91.93.130 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.181 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.41 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.60 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.224.230 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.238.100 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.90.19 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.45.143 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.46.23 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.1.79 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.15.41 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.2.104 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.4.113 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.4.8 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.5.233 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.8.118 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.9.195 -j DROP  # 3 hits
iptables -A INPUT -s 85.217.140.13 -j DROP  # 3 hits