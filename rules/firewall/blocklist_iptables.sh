#!/bin/bash
# LLM Honeypot Intelligence - Firewall Blocklist
# Generated: 2026-06-10 00:05 UTC
# Total: 501 IPs | Blocked: 46 scanners + 33 repeat + 159 active

# Mass Scanners (known infrastructure)
iptables -A INPUT -s 167.94.146.58 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.161 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.112 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.121 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.169 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.54 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.94 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.255 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.48 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.50 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.54 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.61 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.102 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.111 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.161 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.168 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.174 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.175 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.194 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.204 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.22 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.244 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.251 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.57 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.59 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.75 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.84 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.95 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.96 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.162 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.167 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.209 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.215 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.25 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.29 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.48 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.55 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.56 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.74 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.75 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.98 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 66.240.205.34 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 80.82.77.33 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.182 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.73 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.78 -j DROP  # scanner, 1 hits

# Repeat Offenders (>= 10 hits)
iptables -A INPUT -s 175.149.183.33 -j DROP  # 323 hits
iptables -A INPUT -s 85.11.167.11 -j DROP  # 301 hits
iptables -A INPUT -s 139.135.59.149 -j DROP  # 136 hits
iptables -A INPUT -s 85.11.167.7 -j DROP  # 125 hits
iptables -A INPUT -s 176.65.139.41 -j DROP  # 124 hits
iptables -A INPUT -s 104.243.35.104 -j DROP  # 118 hits
iptables -A INPUT -s 104.243.43.7 -j DROP  # 118 hits
iptables -A INPUT -s 103.74.20.164 -j DROP  # 117 hits
iptables -A INPUT -s 223.123.38.125 -j DROP  # 117 hits
iptables -A INPUT -s 45.198.224.18 -j DROP  # 98 hits
iptables -A INPUT -s 85.217.140.37 -j DROP  # 88 hits
iptables -A INPUT -s 66.228.43.62 -j DROP  # 78 hits
iptables -A INPUT -s 188.166.223.76 -j DROP  # 73 hits
iptables -A INPUT -s 104.243.35.94 -j DROP  # 69 hits
iptables -A INPUT -s 94.156.152.234 -j DROP  # 67 hits
iptables -A INPUT -s 104.243.32.126 -j DROP  # 59 hits
iptables -A INPUT -s 104.243.35.120 -j DROP  # 59 hits
iptables -A INPUT -s 104.243.43.19 -j DROP  # 59 hits
iptables -A INPUT -s 198.46.134.48 -j DROP  # 41 hits
iptables -A INPUT -s 45.205.1.5 -j DROP  # 41 hits
iptables -A INPUT -s 45.79.207.223 -j DROP  # 39 hits
iptables -A INPUT -s 120.85.115.7 -j DROP  # 30 hits
iptables -A INPUT -s 5.187.35.26 -j DROP  # 18 hits
iptables -A INPUT -s 45.82.78.108 -j DROP  # 16 hits
iptables -A INPUT -s 93.123.72.166 -j DROP  # 16 hits
iptables -A INPUT -s 107.150.98.86 -j DROP  # 14 hits
iptables -A INPUT -s 3.137.202.87 -j DROP  # 14 hits
iptables -A INPUT -s 45.142.154.112 -j DROP  # 14 hits
iptables -A INPUT -s 45.43.57.157 -j DROP  # 14 hits
iptables -A INPUT -s 45.82.78.103 -j DROP  # 12 hits
iptables -A INPUT -s 45.198.224.5 -j DROP  # 10 hits
iptables -A INPUT -s 20.12.240.74 -j DROP  # 10 hits
iptables -A INPUT -s 47.77.220.169 -j DROP  # 10 hits

# Active Attackers (>= 3 hits)
iptables -A INPUT -s 192.253.248.180 -j DROP  # 9 hits
iptables -A INPUT -s 207.90.244.26 -j DROP  # 9 hits
iptables -A INPUT -s 101.36.97.187 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.56.149 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.156.136 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.119.20 -j DROP  # 8 hits
iptables -A INPUT -s 185.224.128.16 -j DROP  # 8 hits
iptables -A INPUT -s 216.180.246.241 -j DROP  # 8 hits
iptables -A INPUT -s 44.220.185.59 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.102 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.104 -j DROP  # 8 hits
iptables -A INPUT -s 47.242.22.224 -j DROP  # 8 hits
iptables -A INPUT -s 85.217.140.4 -j DROP  # 8 hits
iptables -A INPUT -s 85.217.140.43 -j DROP  # 8 hits
iptables -A INPUT -s 93.123.72.183 -j DROP  # 8 hits
iptables -A INPUT -s 151.243.11.35 -j DROP  # 7 hits
iptables -A INPUT -s 118.194.236.126 -j DROP  # 7 hits
iptables -A INPUT -s 123.58.207.155 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.153.228 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.199.112 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.227.252 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.235.78 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.12.82 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.33.72 -j DROP  # 7 hits
iptables -A INPUT -s 176.65.139.103 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.5.118 -j DROP  # 7 hits
iptables -A INPUT -s 204.76.203.206 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.120 -j DROP  # 7 hits
iptables -A INPUT -s 78.128.112.6 -j DROP  # 7 hits
iptables -A INPUT -s 78.128.113.46 -j DROP  # 7 hits
iptables -A INPUT -s 79.124.59.78 -j DROP  # 7 hits
iptables -A INPUT -s 117.33.242.50 -j DROP  # 6 hits
iptables -A INPUT -s 118.193.39.149 -j DROP  # 6 hits
iptables -A INPUT -s 165.154.172.194 -j DROP  # 6 hits
iptables -A INPUT -s 176.65.139.31 -j DROP  # 6 hits
iptables -A INPUT -s 185.242.226.73 -j DROP  # 6 hits
iptables -A INPUT -s 195.178.110.204 -j DROP  # 6 hits
iptables -A INPUT -s 20.65.224.144 -j DROP  # 6 hits
iptables -A INPUT -s 204.76.203.219 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.186.171 -j DROP  # 6 hits
iptables -A INPUT -s 85.217.140.22 -j DROP  # 6 hits
iptables -A INPUT -s 152.32.211.153 -j DROP  # 5 hits
iptables -A INPUT -s 31.59.160.12 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.185.10 -j DROP  # 5 hits
iptables -A INPUT -s 45.135.193.193 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.13 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.38 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.42 -j DROP  # 5 hits
iptables -A INPUT -s 47.251.122.165 -j DROP  # 5 hits
iptables -A INPUT -s 51.159.110.167 -j DROP  # 5 hits
iptables -A INPUT -s 60.191.137.103 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.195.80 -j DROP  # 5 hits
iptables -A INPUT -s 8.216.16.200 -j DROP  # 5 hits
iptables -A INPUT -s 91.230.168.248 -j DROP  # 5 hits
iptables -A INPUT -s 104.232.79.58 -j DROP  # 4 hits
iptables -A INPUT -s 109.123.251.5 -j DROP  # 4 hits
iptables -A INPUT -s 123.120.108.65 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.213 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.63 -j DROP  # 4 hits
iptables -A INPUT -s 18.191.80.47 -j DROP  # 4 hits
iptables -A INPUT -s 18.217.50.119 -j DROP  # 4 hits
iptables -A INPUT -s 204.76.203.81 -j DROP  # 4 hits
iptables -A INPUT -s 216.180.246.145 -j DROP  # 4 hits
iptables -A INPUT -s 216.180.246.207 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.100 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.105 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.107 -j DROP  # 4 hits
iptables -A INPUT -s 47.236.167.82 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.57 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.71 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.94 -j DROP  # 4 hits
iptables -A INPUT -s 91.191.209.98 -j DROP  # 4 hits
iptables -A INPUT -s 91.231.89.71 -j DROP  # 4 hits
iptables -A INPUT -s 45.148.10.67 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.144 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.174 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.148.147 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.104 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.87 -j DROP  # 3 hits
iptables -A INPUT -s 199.45.154.137 -j DROP  # 3 hits
iptables -A INPUT -s 199.45.155.77 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.12 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.18 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.19 -j DROP  # 3 hits
iptables -A INPUT -s 40.124.175.188 -j DROP  # 3 hits
iptables -A INPUT -s 45.205.1.240 -j DROP  # 3 hits
iptables -A INPUT -s 45.205.1.62 -j DROP  # 3 hits
iptables -A INPUT -s 45.43.60.202 -j DROP  # 3 hits
iptables -A INPUT -s 45.91.64.6 -j DROP  # 3 hits
iptables -A INPUT -s 47.237.121.158 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.134.150 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.137.249 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.139.43 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.141.219 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.114.237 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.123.71 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.163.20 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.178.80 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.42.174 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.80.220 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.90.169 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.101.89 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.125.7 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.19.148 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.242.251 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.248.226 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.34.107 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.48.11 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.52.209 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.64.123 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.68.242 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.128.244 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.167.143 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.202.17 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.213.105 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.244.10 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.53.137 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.71.82 -j DROP  # 3 hits
iptables -A INPUT -s 47.74.26.96 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.219.94 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.231.186 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.233.1 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.100.21 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.109.70 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.129.251 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.141.166 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.203.136 -j DROP  # 3 hits
iptables -A INPUT -s 47.88.104.94 -j DROP  # 3 hits
iptables -A INPUT -s 47.89.247.91 -j DROP  # 3 hits
iptables -A INPUT -s 47.89.248.96 -j DROP  # 3 hits
iptables -A INPUT -s 47.89.251.210 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.135 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.161 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.176 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.201 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.121 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.42 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.61 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.72 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.224.225 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.207.15 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.228.69 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.74.160 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.138.198 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.157.94 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.45.42 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.16.177 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.3.1 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.5.164 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.7.76 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.9.117 -j DROP  # 3 hits
iptables -A INPUT -s 80.94.95.83 -j DROP  # 3 hits
iptables -A INPUT -s 85.217.140.52 -j DROP  # 3 hits
iptables -A INPUT -s 91.191.209.118 -j DROP  # 3 hits
iptables -A INPUT -s 91.196.152.106 -j DROP  # 3 hits
iptables -A INPUT -s 91.196.152.242 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.151 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.30 -j DROP  # 3 hits
iptables -A INPUT -s 91.231.89.202 -j DROP  # 3 hits