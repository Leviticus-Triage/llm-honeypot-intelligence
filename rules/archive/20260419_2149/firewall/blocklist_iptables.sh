#!/bin/bash
# LLM Honeypot Intelligence - Firewall Blocklist
# Generated: 2026-04-19 21:49 UTC
# Total: 520 IPs | Blocked: 44 scanners + 80 repeat + 236 active

# Mass Scanners (known infrastructure)
iptables -A INPUT -s 167.94.146.57 -j DROP  # scanner, 12 hits
iptables -A INPUT -s 167.94.146.62 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 167.94.146.52 -j DROP  # scanner, 9 hits
iptables -A INPUT -s 167.94.146.49 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.58 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.48 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 167.94.146.50 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 167.94.146.51 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 167.94.146.55 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 167.94.146.53 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 167.94.146.56 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 167.94.146.61 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 198.235.24.236 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 167.94.146.60 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 167.94.146.63 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.220 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.56 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 167.94.146.59 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 184.105.139.67 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.69 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.74 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 71.6.147.254 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.54 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 184.105.247.194 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.196 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.197 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.212 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.220 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.225 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.238 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.253 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.39 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.48 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.64 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.104 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.144 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.171 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.212 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.234 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.244 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.103 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.179 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.29 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 80.82.77.202 -j DROP  # scanner, 1 hits

# Repeat Offenders (>= 10 hits)
iptables -A INPUT -s 177.125.137.18 -j DROP  # 2652 hits
iptables -A INPUT -s 104.243.43.7 -j DROP  # 2124 hits
iptables -A INPUT -s 104.243.35.92 -j DROP  # 1856 hits
iptables -A INPUT -s 104.243.35.94 -j DROP  # 1807 hits
iptables -A INPUT -s 51.68.207.118 -j DROP  # 1402 hits
iptables -A INPUT -s 104.243.32.126 -j DROP  # 928 hits
iptables -A INPUT -s 206.221.176.60 -j DROP  # 901 hits
iptables -A INPUT -s 85.217.140.16 -j DROP  # 683 hits
iptables -A INPUT -s 185.91.127.85 -j DROP  # 486 hits
iptables -A INPUT -s 85.11.167.11 -j DROP  # 320 hits
iptables -A INPUT -s 85.217.140.37 -j DROP  # 273 hits
iptables -A INPUT -s 85.217.140.41 -j DROP  # 258 hits
iptables -A INPUT -s 85.217.140.33 -j DROP  # 255 hits
iptables -A INPUT -s 85.217.140.6 -j DROP  # 201 hits
iptables -A INPUT -s 85.217.140.53 -j DROP  # 194 hits
iptables -A INPUT -s 85.217.140.40 -j DROP  # 176 hits
iptables -A INPUT -s 85.217.140.8 -j DROP  # 164 hits
iptables -A INPUT -s 85.217.140.25 -j DROP  # 163 hits
iptables -A INPUT -s 85.217.140.19 -j DROP  # 153 hits
iptables -A INPUT -s 31.14.32.8 -j DROP  # 133 hits
iptables -A INPUT -s 85.217.140.34 -j DROP  # 104 hits
iptables -A INPUT -s 200.124.160.2 -j DROP  # 91 hits
iptables -A INPUT -s 85.217.140.51 -j DROP  # 90 hits
iptables -A INPUT -s 85.217.140.12 -j DROP  # 88 hits
iptables -A INPUT -s 85.217.140.52 -j DROP  # 86 hits
iptables -A INPUT -s 152.42.238.0 -j DROP  # 85 hits
iptables -A INPUT -s 85.217.140.15 -j DROP  # 85 hits
iptables -A INPUT -s 45.205.1.110 -j DROP  # 78 hits
iptables -A INPUT -s 85.217.140.31 -j DROP  # 74 hits
iptables -A INPUT -s 85.217.140.39 -j DROP  # 64 hits
iptables -A INPUT -s 18.116.101.220 -j DROP  # 63 hits
iptables -A INPUT -s 45.205.1.5 -j DROP  # 63 hits
iptables -A INPUT -s 85.217.140.5 -j DROP  # 63 hits
iptables -A INPUT -s 85.217.140.28 -j DROP  # 58 hits
iptables -A INPUT -s 185.150.191.236 -j DROP  # 54 hits
iptables -A INPUT -s 31.14.32.6 -j DROP  # 53 hits
iptables -A INPUT -s 5.29.10.22 -j DROP  # 51 hits
iptables -A INPUT -s 103.84.57.217 -j DROP  # 50 hits
iptables -A INPUT -s 124.29.223.19 -j DROP  # 50 hits
iptables -A INPUT -s 18.218.118.203 -j DROP  # 50 hits
iptables -A INPUT -s 223.123.43.68 -j DROP  # 50 hits
iptables -A INPUT -s 3.134.216.108 -j DROP  # 45 hits
iptables -A INPUT -s 85.217.140.1 -j DROP  # 43 hits
iptables -A INPUT -s 74.218.231.226 -j DROP  # 40 hits
iptables -A INPUT -s 93.123.72.166 -j DROP  # 40 hits
iptables -A INPUT -s 3.131.220.121 -j DROP  # 34 hits
iptables -A INPUT -s 94.102.49.155 -j DROP  # 31 hits
iptables -A INPUT -s 175.107.228.219 -j DROP  # 30 hits
iptables -A INPUT -s 18.189.170.10 -j DROP  # 24 hits
iptables -A INPUT -s 92.63.197.22 -j DROP  # 22 hits
iptables -A INPUT -s 45.205.1.26 -j DROP  # 21 hits
iptables -A INPUT -s 101.36.107.65 -j DROP  # 20 hits
iptables -A INPUT -s 46.151.178.13 -j DROP  # 19 hits
iptables -A INPUT -s 3.130.168.2 -j DROP  # 19 hits
iptables -A INPUT -s 204.76.203.206 -j DROP  # 18 hits
iptables -A INPUT -s 8.155.53.159 -j DROP  # 17 hits
iptables -A INPUT -s 94.140.73.118 -j DROP  # 17 hits
iptables -A INPUT -s 45.82.78.100 -j DROP  # 16 hits
iptables -A INPUT -s 45.82.78.102 -j DROP  # 16 hits
iptables -A INPUT -s 152.32.129.110 -j DROP  # 14 hits
iptables -A INPUT -s 85.217.140.2 -j DROP  # 14 hits
iptables -A INPUT -s 91.191.209.118 -j DROP  # 13 hits
iptables -A INPUT -s 220.92.117.221 -j DROP  # 12 hits
iptables -A INPUT -s 85.217.140.42 -j DROP  # 12 hits
iptables -A INPUT -s 101.36.114.222 -j DROP  # 11 hits
iptables -A INPUT -s 152.32.249.95 -j DROP  # 11 hits
iptables -A INPUT -s 194.88.98.84 -j DROP  # 11 hits
iptables -A INPUT -s 194.88.98.92 -j DROP  # 11 hits
iptables -A INPUT -s 31.56.209.39 -j DROP  # 11 hits
iptables -A INPUT -s 79.124.59.78 -j DROP  # 11 hits
iptables -A INPUT -s 152.32.197.166 -j DROP  # 10 hits
iptables -A INPUT -s 152.32.251.174 -j DROP  # 10 hits
iptables -A INPUT -s 159.75.37.142 -j DROP  # 10 hits
iptables -A INPUT -s 16.58.56.214 -j DROP  # 10 hits
iptables -A INPUT -s 194.88.98.85 -j DROP  # 10 hits
iptables -A INPUT -s 194.88.98.86 -j DROP  # 10 hits
iptables -A INPUT -s 194.88.98.93 -j DROP  # 10 hits
iptables -A INPUT -s 45.142.154.34 -j DROP  # 10 hits
iptables -A INPUT -s 45.142.154.39 -j DROP  # 10 hits
iptables -A INPUT -s 90.160.60.168 -j DROP  # 10 hits

# Active Attackers (>= 3 hits)
iptables -A INPUT -s 3.129.187.38 -j DROP  # 9 hits
iptables -A INPUT -s 124.198.131.185 -j DROP  # 9 hits
iptables -A INPUT -s 18.97.26.109 -j DROP  # 9 hits
iptables -A INPUT -s 194.88.98.88 -j DROP  # 9 hits
iptables -A INPUT -s 194.88.98.90 -j DROP  # 9 hits
iptables -A INPUT -s 36.255.223.98 -j DROP  # 9 hits
iptables -A INPUT -s 44.220.185.93 -j DROP  # 9 hits
iptables -A INPUT -s 45.142.154.101 -j DROP  # 9 hits
iptables -A INPUT -s 3.143.162.210 -j DROP  # 8 hits
iptables -A INPUT -s 106.75.13.37 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.58.187 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.59.10 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.128.169 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.104.88 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.118.215 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.182.221 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.32.235 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.59.168 -j DROP  # 8 hits
iptables -A INPUT -s 185.242.226.126 -j DROP  # 8 hits
iptables -A INPUT -s 194.88.98.94 -j DROP  # 8 hits
iptables -A INPUT -s 204.76.203.73 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.104 -j DROP  # 8 hits
iptables -A INPUT -s 47.77.239.194 -j DROP  # 8 hits
iptables -A INPUT -s 71.6.199.23 -j DROP  # 8 hits
iptables -A INPUT -s 85.11.183.23 -j DROP  # 8 hits
iptables -A INPUT -s 85.217.140.9 -j DROP  # 8 hits
iptables -A INPUT -s 13.86.113.121 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.26.78 -j DROP  # 7 hits
iptables -A INPUT -s 193.142.146.230 -j DROP  # 7 hits
iptables -A INPUT -s 193.176.31.151 -j DROP  # 7 hits
iptables -A INPUT -s 193.176.31.157 -j DROP  # 7 hits
iptables -A INPUT -s 195.140.214.19 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.10 -j DROP  # 7 hits
iptables -A INPUT -s 5.187.35.26 -j DROP  # 7 hits
iptables -A INPUT -s 95.214.52.233 -j DROP  # 7 hits
iptables -A INPUT -s 130.12.180.174 -j DROP  # 6 hits
iptables -A INPUT -s 167.56.1.5 -j DROP  # 6 hits
iptables -A INPUT -s 185.242.226.10 -j DROP  # 6 hits
iptables -A INPUT -s 193.176.31.158 -j DROP  # 6 hits
iptables -A INPUT -s 194.88.98.83 -j DROP  # 6 hits
iptables -A INPUT -s 194.88.98.87 -j DROP  # 6 hits
iptables -A INPUT -s 195.140.214.27 -j DROP  # 6 hits
iptables -A INPUT -s 3.132.26.232 -j DROP  # 6 hits
iptables -A INPUT -s 47.245.130.205 -j DROP  # 6 hits
iptables -A INPUT -s 47.88.7.35 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.186.170 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.195.79 -j DROP  # 6 hits
iptables -A INPUT -s 85.11.183.21 -j DROP  # 6 hits
iptables -A INPUT -s 85.217.140.47 -j DROP  # 6 hits
iptables -A INPUT -s 91.224.92.177 -j DROP  # 5 hits
iptables -A INPUT -s 106.75.13.182 -j DROP  # 5 hits
iptables -A INPUT -s 106.75.15.181 -j DROP  # 5 hits
iptables -A INPUT -s 106.75.9.251 -j DROP  # 5 hits
iptables -A INPUT -s 141.98.10.164 -j DROP  # 5 hits
iptables -A INPUT -s 147.185.133.135 -j DROP  # 5 hits
iptables -A INPUT -s 152.32.132.230 -j DROP  # 5 hits
iptables -A INPUT -s 152.32.216.8 -j DROP  # 5 hits
iptables -A INPUT -s 18.97.26.25 -j DROP  # 5 hits
iptables -A INPUT -s 193.124.20.252 -j DROP  # 5 hits
iptables -A INPUT -s 193.176.31.150 -j DROP  # 5 hits
iptables -A INPUT -s 193.176.31.153 -j DROP  # 5 hits
iptables -A INPUT -s 193.176.31.155 -j DROP  # 5 hits
iptables -A INPUT -s 193.176.31.156 -j DROP  # 5 hits
iptables -A INPUT -s 194.88.98.89 -j DROP  # 5 hits
iptables -A INPUT -s 194.88.98.91 -j DROP  # 5 hits
iptables -A INPUT -s 195.140.214.22 -j DROP  # 5 hits
iptables -A INPUT -s 195.140.214.24 -j DROP  # 5 hits
iptables -A INPUT -s 195.140.214.25 -j DROP  # 5 hits
iptables -A INPUT -s 195.140.214.28 -j DROP  # 5 hits
iptables -A INPUT -s 195.140.214.29 -j DROP  # 5 hits
iptables -A INPUT -s 195.140.214.30 -j DROP  # 5 hits
iptables -A INPUT -s 204.76.203.56 -j DROP  # 5 hits
iptables -A INPUT -s 31.14.32.5 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.188.201 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.113 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.116 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.16 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.18 -j DROP  # 5 hits
iptables -A INPUT -s 47.237.199.128 -j DROP  # 5 hits
iptables -A INPUT -s 47.245.139.47 -j DROP  # 5 hits
iptables -A INPUT -s 47.84.194.245 -j DROP  # 5 hits
iptables -A INPUT -s 5.61.209.24 -j DROP  # 5 hits
iptables -A INPUT -s 8.216.16.169 -j DROP  # 5 hits
iptables -A INPUT -s 85.217.140.29 -j DROP  # 5 hits
iptables -A INPUT -s 93.123.109.183 -j DROP  # 5 hits
iptables -A INPUT -s 93.174.95.106 -j DROP  # 5 hits
iptables -A INPUT -s 98.80.4.112 -j DROP  # 5 hits
iptables -A INPUT -s 104.232.79.58 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.210.52 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.210.55 -j DROP  # 4 hits
iptables -A INPUT -s 118.193.59.194 -j DROP  # 4 hits
iptables -A INPUT -s 13.89.124.221 -j DROP  # 4 hits
iptables -A INPUT -s 135.237.124.11 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.230 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.133.109 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.133.130 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.133.143 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.133.219 -j DROP  # 4 hits
iptables -A INPUT -s 170.39.218.48 -j DROP  # 4 hits
iptables -A INPUT -s 185.224.128.16 -j DROP  # 4 hits
iptables -A INPUT -s 193.124.20.247 -j DROP  # 4 hits
iptables -A INPUT -s 193.176.31.152 -j DROP  # 4 hits
iptables -A INPUT -s 193.176.31.154 -j DROP  # 4 hits
iptables -A INPUT -s 195.140.214.20 -j DROP  # 4 hits
iptables -A INPUT -s 195.140.214.26 -j DROP  # 4 hits
iptables -A INPUT -s 204.76.203.215 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.211.33 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.103 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.105 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.106 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.107 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.108 -j DROP  # 4 hits
iptables -A INPUT -s 47.245.129.215 -j DROP  # 4 hits
iptables -A INPUT -s 47.245.9.17 -j DROP  # 4 hits
iptables -A INPUT -s 47.251.107.39 -j DROP  # 4 hits
iptables -A INPUT -s 47.251.113.207 -j DROP  # 4 hits
iptables -A INPUT -s 47.254.32.206 -j DROP  # 4 hits
iptables -A INPUT -s 47.77.233.169 -j DROP  # 4 hits
iptables -A INPUT -s 51.159.110.167 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.185 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.186.182 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.64 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.65 -j DROP  # 4 hits
iptables -A INPUT -s 8.209.102.92 -j DROP  # 4 hits
iptables -A INPUT -s 85.11.183.19 -j DROP  # 4 hits
iptables -A INPUT -s 85.11.183.25 -j DROP  # 4 hits
iptables -A INPUT -s 85.11.183.27 -j DROP  # 4 hits
iptables -A INPUT -s 45.91.22.22 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.139.254 -j DROP  # 3 hits
iptables -A INPUT -s 101.201.38.226 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.54 -j DROP  # 3 hits
iptables -A INPUT -s 120.86.119.165 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.102 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.194 -j DROP  # 3 hits
iptables -A INPUT -s 178.83.200.2 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.104 -j DROP  # 3 hits
iptables -A INPUT -s 193.124.20.254 -j DROP  # 3 hits
iptables -A INPUT -s 193.176.31.147 -j DROP  # 3 hits
iptables -A INPUT -s 193.176.31.149 -j DROP  # 3 hits
iptables -A INPUT -s 195.178.110.204 -j DROP  # 3 hits
iptables -A INPUT -s 198.50.152.30 -j DROP  # 3 hits
iptables -A INPUT -s 199.45.154.149 -j DROP  # 3 hits
iptables -A INPUT -s 207.154.228.110 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.26 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.4 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.6 -j DROP  # 3 hits
iptables -A INPUT -s 35.203.210.118 -j DROP  # 3 hits
iptables -A INPUT -s 35.203.210.191 -j DROP  # 3 hits
iptables -A INPUT -s 35.203.210.247 -j DROP  # 3 hits
iptables -A INPUT -s 35.203.211.113 -j DROP  # 3 hits
iptables -A INPUT -s 45.135.193.118 -j DROP  # 3 hits
iptables -A INPUT -s 47.237.100.187 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.133.99 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.136.243 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.138.87 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.139.222 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.12.201 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.44.127 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.93.19 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.94.154 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.94.185 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.101.89 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.117.128 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.122.183 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.125.100 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.125.118 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.171.255 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.179.212 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.179.221 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.188.112 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.253.98 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.35.109 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.42.170 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.67.227 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.72.187 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.81.7 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.84.116 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.93.194 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.95.239 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.143.201 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.147.64 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.159.226 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.170.239 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.179.129 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.195.162 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.213.90 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.46.23 -j DROP  # 3 hits
iptables -A INPUT -s 47.74.13.101 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.215.113 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.102.149 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.102.160 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.103.150 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.103.255 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.106.18 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.140.90 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.141.248 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.184.157 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.203.86 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.205.149 -j DROP  # 3 hits
iptables -A INPUT -s 47.89.247.18 -j DROP  # 3 hits
iptables -A INPUT -s 47.91.79.97 -j DROP  # 3 hits
iptables -A INPUT -s 47.91.92.212 -j DROP  # 3 hits
iptables -A INPUT -s 64.89.163.235 -j DROP  # 3 hits
iptables -A INPUT -s 65.49.1.108 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.181 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.33 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.195 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.198 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.33 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.48 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.63 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.73 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.82 -j DROP  # 3 hits
iptables -A INPUT -s 78.128.113.46 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.209.96 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.70.202 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.138.198 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.30.254 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.37.42 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.12.63 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.4.57 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.4.72 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.6.222 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.7.115 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.7.143 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.7.66 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.8.45 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.8.87 -j DROP  # 3 hits
iptables -A INPUT -s 8.219.104.8 -j DROP  # 3 hits
iptables -A INPUT -s 80.82.70.133 -j DROP  # 3 hits
iptables -A INPUT -s 85.217.140.11 -j DROP  # 3 hits
iptables -A INPUT -s 85.217.140.24 -j DROP  # 3 hits
iptables -A INPUT -s 85.217.140.36 -j DROP  # 3 hits
iptables -A INPUT -s 85.217.140.50 -j DROP  # 3 hits
iptables -A INPUT -s 86.54.31.32 -j DROP  # 3 hits
iptables -A INPUT -s 86.54.31.44 -j DROP  # 3 hits