#!/bin/bash
# LLM Honeypot Intelligence - Firewall Blocklist
# Generated: 2026-04-14 11:48 UTC
# Total: 558 IPs | Blocked: 41 scanners + 126 repeat + 339 active

# Mass Scanners (known infrastructure)
iptables -A INPUT -s 167.94.146.48 -j DROP  # scanner, 21 hits
iptables -A INPUT -s 167.94.146.62 -j DROP  # scanner, 21 hits
iptables -A INPUT -s 167.94.146.61 -j DROP  # scanner, 20 hits
iptables -A INPUT -s 167.94.146.59 -j DROP  # scanner, 20 hits
iptables -A INPUT -s 167.94.146.53 -j DROP  # scanner, 19 hits
iptables -A INPUT -s 167.94.146.56 -j DROP  # scanner, 19 hits
iptables -A INPUT -s 167.94.146.49 -j DROP  # scanner, 16 hits
iptables -A INPUT -s 167.94.146.63 -j DROP  # scanner, 15 hits
iptables -A INPUT -s 167.94.146.55 -j DROP  # scanner, 14 hits
iptables -A INPUT -s 167.94.146.54 -j DROP  # scanner, 13 hits
iptables -A INPUT -s 167.94.146.52 -j DROP  # scanner, 12 hits
iptables -A INPUT -s 167.94.146.60 -j DROP  # scanner, 12 hits
iptables -A INPUT -s 167.94.146.51 -j DROP  # scanner, 11 hits
iptables -A INPUT -s 184.105.247.195 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 167.94.146.50 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 167.94.146.57 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 71.6.135.131 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.58 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 184.105.247.196 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 205.210.31.212 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 184.105.247.252 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 205.210.31.209 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 66.240.205.34 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 184.105.139.68 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.174 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.216 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.252 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.53 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.72 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.103 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.250 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.91 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 184.105.139.70 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 184.105.247.194 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.116 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.102 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.203 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.46 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 205.210.31.11 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 205.210.31.214 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 74.82.47.3 -j DROP  # scanner, 1 hits

# Repeat Offenders (>= 10 hits)
iptables -A INPUT -s 176.65.132.254 -j DROP  # 10379 hits
iptables -A INPUT -s 87.251.64.159 -j DROP  # 2676 hits
iptables -A INPUT -s 104.243.32.126 -j DROP  # 1187 hits
iptables -A INPUT -s 85.11.167.11 -j DROP  # 448 hits
iptables -A INPUT -s 104.243.43.7 -j DROP  # 251 hits
iptables -A INPUT -s 80.94.92.182 -j DROP  # 202 hits
iptables -A INPUT -s 104.243.35.104 -j DROP  # 179 hits
iptables -A INPUT -s 206.221.176.60 -j DROP  # 178 hits
iptables -A INPUT -s 45.205.1.5 -j DROP  # 161 hits
iptables -A INPUT -s 104.243.32.235 -j DROP  # 150 hits
iptables -A INPUT -s 45.205.1.110 -j DROP  # 147 hits
iptables -A INPUT -s 178.221.54.184 -j DROP  # 129 hits
iptables -A INPUT -s 18.218.118.203 -j DROP  # 128 hits
iptables -A INPUT -s 81.29.142.100 -j DROP  # 119 hits
iptables -A INPUT -s 16.58.56.214 -j DROP  # 115 hits
iptables -A INPUT -s 92.118.39.72 -j DROP  # 106 hits
iptables -A INPUT -s 18.116.101.220 -j DROP  # 105 hits
iptables -A INPUT -s 3.129.187.38 -j DROP  # 102 hits
iptables -A INPUT -s 3.131.220.121 -j DROP  # 99 hits
iptables -A INPUT -s 2.57.122.238 -j DROP  # 86 hits
iptables -A INPUT -s 45.33.114.45 -j DROP  # 81 hits
iptables -A INPUT -s 3.130.168.2 -j DROP  # 77 hits
iptables -A INPUT -s 3.132.26.232 -j DROP  # 65 hits
iptables -A INPUT -s 46.151.178.13 -j DROP  # 55 hits
iptables -A INPUT -s 104.243.34.165 -j DROP  # 54 hits
iptables -A INPUT -s 139.135.41.125 -j DROP  # 50 hits
iptables -A INPUT -s 103.199.123.32 -j DROP  # 46 hits
iptables -A INPUT -s 204.76.203.206 -j DROP  # 43 hits
iptables -A INPUT -s 45.205.1.26 -j DROP  # 42 hits
iptables -A INPUT -s 93.123.72.166 -j DROP  # 41 hits
iptables -A INPUT -s 104.248.54.194 -j DROP  # 39 hits
iptables -A INPUT -s 134.122.28.163 -j DROP  # 39 hits
iptables -A INPUT -s 134.209.56.54 -j DROP  # 39 hits
iptables -A INPUT -s 138.68.58.48 -j DROP  # 39 hits
iptables -A INPUT -s 147.182.209.206 -j DROP  # 39 hits
iptables -A INPUT -s 157.230.13.255 -j DROP  # 39 hits
iptables -A INPUT -s 157.245.168.43 -j DROP  # 39 hits
iptables -A INPUT -s 157.245.173.26 -j DROP  # 39 hits
iptables -A INPUT -s 159.223.187.136 -j DROP  # 39 hits
iptables -A INPUT -s 159.223.189.59 -j DROP  # 39 hits
iptables -A INPUT -s 165.232.61.17 -j DROP  # 39 hits
iptables -A INPUT -s 167.172.121.65 -j DROP  # 39 hits
iptables -A INPUT -s 167.71.31.191 -j DROP  # 39 hits
iptables -A INPUT -s 170.187.158.208 -j DROP  # 39 hits
iptables -A INPUT -s 173.255.226.126 -j DROP  # 39 hits
iptables -A INPUT -s 173.255.226.239 -j DROP  # 39 hits
iptables -A INPUT -s 173.255.232.113 -j DROP  # 39 hits
iptables -A INPUT -s 192.81.129.161 -j DROP  # 39 hits
iptables -A INPUT -s 192.81.129.166 -j DROP  # 39 hits
iptables -A INPUT -s 204.48.29.133 -j DROP  # 39 hits
iptables -A INPUT -s 206.189.222.234 -j DROP  # 39 hits
iptables -A INPUT -s 23.239.29.27 -j DROP  # 39 hits
iptables -A INPUT -s 45.33.102.121 -j DROP  # 39 hits
iptables -A INPUT -s 45.33.102.13 -j DROP  # 39 hits
iptables -A INPUT -s 45.33.114.92 -j DROP  # 39 hits
iptables -A INPUT -s 45.33.125.59 -j DROP  # 39 hits
iptables -A INPUT -s 64.227.93.166 -j DROP  # 39 hits
iptables -A INPUT -s 3.151.241.153 -j DROP  # 38 hits
iptables -A INPUT -s 185.150.191.236 -j DROP  # 36 hits
iptables -A INPUT -s 92.118.39.76 -j DROP  # 34 hits
iptables -A INPUT -s 3.143.162.210 -j DROP  # 32 hits
iptables -A INPUT -s 81.29.142.6 -j DROP  # 31 hits
iptables -A INPUT -s 45.153.34.204 -j DROP  # 28 hits
iptables -A INPUT -s 128.199.225.7 -j DROP  # 25 hits
iptables -A INPUT -s 37.44.238.107 -j DROP  # 25 hits
iptables -A INPUT -s 185.91.127.85 -j DROP  # 24 hits
iptables -A INPUT -s 3.134.216.108 -j DROP  # 23 hits
iptables -A INPUT -s 103.97.215.11 -j DROP  # 22 hits
iptables -A INPUT -s 51.158.205.203 -j DROP  # 22 hits
iptables -A INPUT -s 121.199.48.149 -j DROP  # 21 hits
iptables -A INPUT -s 207.90.244.26 -j DROP  # 21 hits
iptables -A INPUT -s 207.90.244.4 -j DROP  # 21 hits
iptables -A INPUT -s 92.63.197.22 -j DROP  # 20 hits
iptables -A INPUT -s 152.32.233.95 -j DROP  # 19 hits
iptables -A INPUT -s 185.150.191.165 -j DROP  # 19 hits
iptables -A INPUT -s 80.66.83.80 -j DROP  # 19 hits
iptables -A INPUT -s 110.36.80.166 -j DROP  # 18 hits
iptables -A INPUT -s 209.222.101.194 -j DROP  # 18 hits
iptables -A INPUT -s 87.251.64.141 -j DROP  # 18 hits
iptables -A INPUT -s 95.214.52.233 -j DROP  # 18 hits
iptables -A INPUT -s 104.243.35.92 -j DROP  # 17 hits
iptables -A INPUT -s 118.193.46.233 -j DROP  # 16 hits
iptables -A INPUT -s 193.124.20.242 -j DROP  # 16 hits
iptables -A INPUT -s 194.88.98.85 -j DROP  # 16 hits
iptables -A INPUT -s 45.148.10.121 -j DROP  # 16 hits
iptables -A INPUT -s 204.76.203.215 -j DROP  # 15 hits
iptables -A INPUT -s 207.90.244.19 -j DROP  # 15 hits
iptables -A INPUT -s 45.135.194.113 -j DROP  # 15 hits
iptables -A INPUT -s 5.187.35.142 -j DROP  # 15 hits
iptables -A INPUT -s 64.227.4.54 -j DROP  # 15 hits
iptables -A INPUT -s 93.123.109.183 -j DROP  # 15 hits
iptables -A INPUT -s 112.5.73.216 -j DROP  # 14 hits
iptables -A INPUT -s 78.128.113.46 -j DROP  # 14 hits
iptables -A INPUT -s 65.49.20.68 -j DROP  # 13 hits
iptables -A INPUT -s 106.225.216.171 -j DROP  # 12 hits
iptables -A INPUT -s 130.12.180.174 -j DROP  # 12 hits
iptables -A INPUT -s 185.180.141.32 -j DROP  # 12 hits
iptables -A INPUT -s 185.224.128.16 -j DROP  # 12 hits
iptables -A INPUT -s 193.176.31.157 -j DROP  # 12 hits
iptables -A INPUT -s 207.90.244.18 -j DROP  # 12 hits
iptables -A INPUT -s 45.156.128.86 -j DROP  # 12 hits
iptables -A INPUT -s 45.82.78.100 -j DROP  # 12 hits
iptables -A INPUT -s 45.82.78.102 -j DROP  # 12 hits
iptables -A INPUT -s 47.250.163.215 -j DROP  # 12 hits
iptables -A INPUT -s 79.124.59.78 -j DROP  # 12 hits
iptables -A INPUT -s 91.191.209.118 -j DROP  # 12 hits
iptables -A INPUT -s 106.75.13.117 -j DROP  # 11 hits
iptables -A INPUT -s 193.142.146.230 -j DROP  # 11 hits
iptables -A INPUT -s 193.176.31.153 -j DROP  # 11 hits
iptables -A INPUT -s 193.176.31.154 -j DROP  # 11 hits
iptables -A INPUT -s 194.88.98.86 -j DROP  # 11 hits
iptables -A INPUT -s 204.76.203.56 -j DROP  # 11 hits
iptables -A INPUT -s 51.159.110.167 -j DROP  # 11 hits
iptables -A INPUT -s 193.124.20.254 -j DROP  # 10 hits
iptables -A INPUT -s 138.197.81.20 -j DROP  # 10 hits
iptables -A INPUT -s 141.98.10.164 -j DROP  # 10 hits
iptables -A INPUT -s 170.39.218.48 -j DROP  # 10 hits
iptables -A INPUT -s 185.242.226.10 -j DROP  # 10 hits
iptables -A INPUT -s 193.124.20.250 -j DROP  # 10 hits
iptables -A INPUT -s 193.176.31.147 -j DROP  # 10 hits
iptables -A INPUT -s 194.88.98.92 -j DROP  # 10 hits
iptables -A INPUT -s 37.10.113.217 -j DROP  # 10 hits
iptables -A INPUT -s 45.156.128.91 -j DROP  # 10 hits
iptables -A INPUT -s 45.156.129.85 -j DROP  # 10 hits
iptables -A INPUT -s 47.84.140.197 -j DROP  # 10 hits
iptables -A INPUT -s 8.135.238.47 -j DROP  # 10 hits

# Active Attackers (>= 3 hits)
iptables -A INPUT -s 37.10.113.214 -j DROP  # 9 hits
iptables -A INPUT -s 118.194.236.137 -j DROP  # 9 hits
iptables -A INPUT -s 128.14.227.37 -j DROP  # 9 hits
iptables -A INPUT -s 147.185.132.180 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.149.19 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.149.246 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.150.215 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.164.139 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.178.47 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.206.49 -j DROP  # 9 hits
iptables -A INPUT -s 162.243.84.219 -j DROP  # 9 hits
iptables -A INPUT -s 165.154.119.158 -j DROP  # 9 hits
iptables -A INPUT -s 165.154.129.130 -j DROP  # 9 hits
iptables -A INPUT -s 165.154.138.33 -j DROP  # 9 hits
iptables -A INPUT -s 193.124.20.245 -j DROP  # 9 hits
iptables -A INPUT -s 193.124.20.251 -j DROP  # 9 hits
iptables -A INPUT -s 194.88.98.89 -j DROP  # 9 hits
iptables -A INPUT -s 207.90.244.17 -j DROP  # 9 hits
iptables -A INPUT -s 207.90.244.6 -j DROP  # 9 hits
iptables -A INPUT -s 37.10.113.221 -j DROP  # 9 hits
iptables -A INPUT -s 176.65.148.37 -j DROP  # 8 hits
iptables -A INPUT -s 193.124.20.246 -j DROP  # 8 hits
iptables -A INPUT -s 65.49.20.69 -j DROP  # 8 hits
iptables -A INPUT -s 107.150.117.219 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.32.88 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.58.125 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.58.20 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.65.209 -j DROP  # 8 hits
iptables -A INPUT -s 118.26.37.105 -j DROP  # 8 hits
iptables -A INPUT -s 124.198.131.185 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.197.12 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.197.121 -j DROP  # 8 hits
iptables -A INPUT -s 156.229.16.142 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.100.42 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.120.30 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.162.102 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.163.199 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.182.72 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.221.175 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.32.235 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.36.245 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.59.168 -j DROP  # 8 hits
iptables -A INPUT -s 18.97.19.178 -j DROP  # 8 hits
iptables -A INPUT -s 185.226.197.7 -j DROP  # 8 hits
iptables -A INPUT -s 193.124.20.243 -j DROP  # 8 hits
iptables -A INPUT -s 193.176.31.150 -j DROP  # 8 hits
iptables -A INPUT -s 193.176.31.152 -j DROP  # 8 hits
iptables -A INPUT -s 194.88.98.83 -j DROP  # 8 hits
iptables -A INPUT -s 194.88.98.88 -j DROP  # 8 hits
iptables -A INPUT -s 222.88.163.204 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.106 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.108 -j DROP  # 8 hits
iptables -A INPUT -s 47.251.49.115 -j DROP  # 8 hits
iptables -A INPUT -s 65.49.20.66 -j DROP  # 8 hits
iptables -A INPUT -s 66.132.195.73 -j DROP  # 8 hits
iptables -A INPUT -s 103.203.57.20 -j DROP  # 7 hits
iptables -A INPUT -s 109.105.210.62 -j DROP  # 7 hits
iptables -A INPUT -s 176.120.22.135 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.26.4 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.26.61 -j DROP  # 7 hits
iptables -A INPUT -s 185.180.141.7 -j DROP  # 7 hits
iptables -A INPUT -s 193.124.20.249 -j DROP  # 7 hits
iptables -A INPUT -s 193.124.20.252 -j DROP  # 7 hits
iptables -A INPUT -s 193.124.20.253 -j DROP  # 7 hits
iptables -A INPUT -s 193.176.31.148 -j DROP  # 7 hits
iptables -A INPUT -s 193.176.31.149 -j DROP  # 7 hits
iptables -A INPUT -s 193.176.31.155 -j DROP  # 7 hits
iptables -A INPUT -s 193.176.31.156 -j DROP  # 7 hits
iptables -A INPUT -s 194.88.98.87 -j DROP  # 7 hits
iptables -A INPUT -s 194.88.98.94 -j DROP  # 7 hits
iptables -A INPUT -s 221.228.10.226 -j DROP  # 7 hits
iptables -A INPUT -s 37.10.113.211 -j DROP  # 7 hits
iptables -A INPUT -s 37.10.113.213 -j DROP  # 7 hits
iptables -A INPUT -s 37.10.113.220 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.196 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.90 -j DROP  # 7 hits
iptables -A INPUT -s 66.132.172.110 -j DROP  # 7 hits
iptables -A INPUT -s 66.132.195.66 -j DROP  # 7 hits
iptables -A INPUT -s 80.94.95.83 -j DROP  # 7 hits
iptables -A INPUT -s 98.80.4.70 -j DROP  # 7 hits
iptables -A INPUT -s 1.95.195.50 -j DROP  # 6 hits
iptables -A INPUT -s 106.75.11.5 -j DROP  # 6 hits
iptables -A INPUT -s 109.105.209.12 -j DROP  # 6 hits
iptables -A INPUT -s 112.91.141.33 -j DROP  # 6 hits
iptables -A INPUT -s 152.32.180.86 -j DROP  # 6 hits
iptables -A INPUT -s 157.255.35.242 -j DROP  # 6 hits
iptables -A INPUT -s 165.154.163.10 -j DROP  # 6 hits
iptables -A INPUT -s 185.226.197.32 -j DROP  # 6 hits
iptables -A INPUT -s 185.242.226.73 -j DROP  # 6 hits
iptables -A INPUT -s 193.124.20.244 -j DROP  # 6 hits
iptables -A INPUT -s 193.124.20.247 -j DROP  # 6 hits
iptables -A INPUT -s 193.176.31.151 -j DROP  # 6 hits
iptables -A INPUT -s 193.176.31.158 -j DROP  # 6 hits
iptables -A INPUT -s 207.90.244.12 -j DROP  # 6 hits
iptables -A INPUT -s 216.218.206.68 -j DROP  # 6 hits
iptables -A INPUT -s 45.156.128.94 -j DROP  # 6 hits
iptables -A INPUT -s 45.156.129.87 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.195.43 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.195.55 -j DROP  # 6 hits
iptables -A INPUT -s 71.6.199.23 -j DROP  # 6 hits
iptables -A INPUT -s 86.54.31.44 -j DROP  # 6 hits
iptables -A INPUT -s 94.154.35.122 -j DROP  # 6 hits
iptables -A INPUT -s 80.94.92.168 -j DROP  # 5 hits
iptables -A INPUT -s 101.36.111.179 -j DROP  # 5 hits
iptables -A INPUT -s 106.75.14.37 -j DROP  # 5 hits
iptables -A INPUT -s 106.75.2.51 -j DROP  # 5 hits
iptables -A INPUT -s 109.105.209.2 -j DROP  # 5 hits
iptables -A INPUT -s 109.105.209.7 -j DROP  # 5 hits
iptables -A INPUT -s 109.105.210.55 -j DROP  # 5 hits
iptables -A INPUT -s 118.193.38.178 -j DROP  # 5 hits
iptables -A INPUT -s 118.193.40.131 -j DROP  # 5 hits
iptables -A INPUT -s 118.193.56.235 -j DROP  # 5 hits
iptables -A INPUT -s 141.98.8.122 -j DROP  # 5 hits
iptables -A INPUT -s 147.185.132.195 -j DROP  # 5 hits
iptables -A INPUT -s 147.185.132.69 -j DROP  # 5 hits
iptables -A INPUT -s 148.153.188.254 -j DROP  # 5 hits
iptables -A INPUT -s 152.32.192.230 -j DROP  # 5 hits
iptables -A INPUT -s 152.32.211.139 -j DROP  # 5 hits
iptables -A INPUT -s 164.92.154.78 -j DROP  # 5 hits
iptables -A INPUT -s 178.128.252.70 -j DROP  # 5 hits
iptables -A INPUT -s 178.16.55.208 -j DROP  # 5 hits
iptables -A INPUT -s 18.222.153.198 -j DROP  # 5 hits
iptables -A INPUT -s 193.124.20.248 -j DROP  # 5 hits
iptables -A INPUT -s 194.88.98.90 -j DROP  # 5 hits
iptables -A INPUT -s 195.140.214.28 -j DROP  # 5 hits
iptables -A INPUT -s 195.184.76.33 -j DROP  # 5 hits
iptables -A INPUT -s 20.64.106.38 -j DROP  # 5 hits
iptables -A INPUT -s 20.84.144.171 -j DROP  # 5 hits
iptables -A INPUT -s 216.218.206.67 -j DROP  # 5 hits
iptables -A INPUT -s 23.94.252.104 -j DROP  # 5 hits
iptables -A INPUT -s 37.10.113.216 -j DROP  # 5 hits
iptables -A INPUT -s 37.10.113.218 -j DROP  # 5 hits
iptables -A INPUT -s 37.10.113.219 -j DROP  # 5 hits
iptables -A INPUT -s 37.10.113.222 -j DROP  # 5 hits
iptables -A INPUT -s 40.76.124.195 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.185.122 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.114 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.13 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.15 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.44 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.88 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.90 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.95 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.128.61 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.128.88 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.128.89 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.128.93 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.129.65 -j DROP  # 5 hits
iptables -A INPUT -s 47.237.204.8 -j DROP  # 5 hits
iptables -A INPUT -s 47.251.182.239 -j DROP  # 5 hits
iptables -A INPUT -s 47.251.250.61 -j DROP  # 5 hits
iptables -A INPUT -s 47.84.204.199 -j DROP  # 5 hits
iptables -A INPUT -s 62.164.177.41 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.186.164 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.186.187 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.186.194 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.186.205 -j DROP  # 5 hits
iptables -A INPUT -s 80.66.83.43 -j DROP  # 5 hits
iptables -A INPUT -s 91.230.168.234 -j DROP  # 5 hits
iptables -A INPUT -s 91.231.89.15 -j DROP  # 5 hits
iptables -A INPUT -s 91.231.89.53 -j DROP  # 5 hits
iptables -A INPUT -s 94.102.49.193 -j DROP  # 5 hits
iptables -A INPUT -s 213.177.179.101 -j DROP  # 4 hits
iptables -A INPUT -s 72.56.5.167 -j DROP  # 4 hits
iptables -A INPUT -s 95.214.53.42 -j DROP  # 4 hits
iptables -A INPUT -s 199.45.154.119 -j DROP  # 4 hits
iptables -A INPUT -s 31.57.216.224 -j DROP  # 4 hits
iptables -A INPUT -s 101.36.121.22 -j DROP  # 4 hits
iptables -A INPUT -s 104.248.141.14 -j DROP  # 4 hits
iptables -A INPUT -s 104.248.252.32 -j DROP  # 4 hits
iptables -A INPUT -s 104.248.92.153 -j DROP  # 4 hits
iptables -A INPUT -s 107.170.10.90 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.209.3 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.210.74 -j DROP  # 4 hits
iptables -A INPUT -s 114.215.197.233 -j DROP  # 4 hits
iptables -A INPUT -s 134.122.57.144 -j DROP  # 4 hits
iptables -A INPUT -s 134.122.61.164 -j DROP  # 4 hits
iptables -A INPUT -s 134.209.196.229 -j DROP  # 4 hits
iptables -A INPUT -s 142.93.134.60 -j DROP  # 4 hits
iptables -A INPUT -s 142.93.142.53 -j DROP  # 4 hits
iptables -A INPUT -s 142.93.230.145 -j DROP  # 4 hits
iptables -A INPUT -s 143.198.70.223 -j DROP  # 4 hits
iptables -A INPUT -s 146.190.29.216 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.171 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.64 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.99 -j DROP  # 4 hits
iptables -A INPUT -s 159.223.0.173 -j DROP  # 4 hits
iptables -A INPUT -s 159.223.15.24 -j DROP  # 4 hits
iptables -A INPUT -s 159.223.237.22 -j DROP  # 4 hits
iptables -A INPUT -s 159.65.125.60 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.163 -j DROP  # 4 hits
iptables -A INPUT -s 164.90.228.126 -j DROP  # 4 hits
iptables -A INPUT -s 164.92.212.13 -j DROP  # 4 hits
iptables -A INPUT -s 164.92.212.43 -j DROP  # 4 hits
iptables -A INPUT -s 165.22.201.147 -j DROP  # 4 hits
iptables -A INPUT -s 165.227.158.57 -j DROP  # 4 hits
iptables -A INPUT -s 167.172.38.128 -j DROP  # 4 hits
iptables -A INPUT -s 167.172.96.40 -j DROP  # 4 hits
iptables -A INPUT -s 167.71.66.243 -j DROP  # 4 hits
iptables -A INPUT -s 167.99.33.241 -j DROP  # 4 hits
iptables -A INPUT -s 176.32.193.16 -j DROP  # 4 hits
iptables -A INPUT -s 176.65.132.107 -j DROP  # 4 hits
iptables -A INPUT -s 176.65.134.34 -j DROP  # 4 hits
iptables -A INPUT -s 178.62.192.102 -j DROP  # 4 hits
iptables -A INPUT -s 178.62.199.172 -j DROP  # 4 hits
iptables -A INPUT -s 178.62.205.102 -j DROP  # 4 hits
iptables -A INPUT -s 178.62.247.76 -j DROP  # 4 hits
iptables -A INPUT -s 178.62.252.55 -j DROP  # 4 hits
iptables -A INPUT -s 185.242.226.85 -j DROP  # 4 hits
iptables -A INPUT -s 188.166.102.152 -j DROP  # 4 hits
iptables -A INPUT -s 188.166.104.121 -j DROP  # 4 hits
iptables -A INPUT -s 188.166.115.197 -j DROP  # 4 hits
iptables -A INPUT -s 188.166.127.18 -j DROP  # 4 hits
iptables -A INPUT -s 188.166.14.63 -j DROP  # 4 hits
iptables -A INPUT -s 188.166.164.250 -j DROP  # 4 hits
iptables -A INPUT -s 188.166.23.68 -j DROP  # 4 hits
iptables -A INPUT -s 188.166.30.242 -j DROP  # 4 hits
iptables -A INPUT -s 188.166.62.15 -j DROP  # 4 hits
iptables -A INPUT -s 188.166.97.59 -j DROP  # 4 hits
iptables -A INPUT -s 194.88.98.91 -j DROP  # 4 hits
iptables -A INPUT -s 195.140.214.18 -j DROP  # 4 hits
iptables -A INPUT -s 195.140.214.22 -j DROP  # 4 hits
iptables -A INPUT -s 195.140.214.23 -j DROP  # 4 hits
iptables -A INPUT -s 195.140.214.24 -j DROP  # 4 hits
iptables -A INPUT -s 195.140.214.29 -j DROP  # 4 hits
iptables -A INPUT -s 195.184.76.135 -j DROP  # 4 hits
iptables -A INPUT -s 195.184.76.142 -j DROP  # 4 hits
iptables -A INPUT -s 195.184.76.205 -j DROP  # 4 hits
iptables -A INPUT -s 20.102.91.36 -j DROP  # 4 hits
iptables -A INPUT -s 20.163.20.206 -j DROP  # 4 hits
iptables -A INPUT -s 20.55.3.202 -j DROP  # 4 hits
iptables -A INPUT -s 20.64.105.156 -j DROP  # 4 hits
iptables -A INPUT -s 209.38.101.100 -j DROP  # 4 hits
iptables -A INPUT -s 209.38.204.16 -j DROP  # 4 hits
iptables -A INPUT -s 209.38.229.158 -j DROP  # 4 hits
iptables -A INPUT -s 209.38.32.149 -j DROP  # 4 hits
iptables -A INPUT -s 209.38.34.218 -j DROP  # 4 hits
iptables -A INPUT -s 209.38.97.33 -j DROP  # 4 hits
iptables -A INPUT -s 37.10.113.210 -j DROP  # 4 hits
iptables -A INPUT -s 37.10.113.212 -j DROP  # 4 hits
iptables -A INPUT -s 37.10.113.215 -j DROP  # 4 hits
iptables -A INPUT -s 43.228.157.45 -j DROP  # 4 hits
iptables -A INPUT -s 44.220.188.120 -j DROP  # 4 hits
iptables -A INPUT -s 45.153.34.231 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.128.87 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.129.60 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.129.80 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.129.86 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.129.90 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.103 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.104 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.107 -j DROP  # 4 hits
iptables -A INPUT -s 45.91.64.7 -j DROP  # 4 hits
iptables -A INPUT -s 47.245.13.179 -j DROP  # 4 hits
iptables -A INPUT -s 47.245.138.36 -j DROP  # 4 hits
iptables -A INPUT -s 47.251.115.200 -j DROP  # 4 hits
iptables -A INPUT -s 47.254.159.226 -j DROP  # 4 hits
iptables -A INPUT -s 5.61.209.107 -j DROP  # 4 hits
iptables -A INPUT -s 58.212.237.19 -j DROP  # 4 hits
iptables -A INPUT -s 64.227.79.63 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.129 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.194 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.201 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.209 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.40 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.42 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.97 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.186.160 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.186.174 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.186.188 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.33 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.79 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.80 -j DROP  # 4 hits
iptables -A INPUT -s 66.240.236.119 -j DROP  # 4 hits
iptables -A INPUT -s 68.183.77.77 -j DROP  # 4 hits
iptables -A INPUT -s 68.183.8.254 -j DROP  # 4 hits
iptables -A INPUT -s 71.6.158.166 -j DROP  # 4 hits
iptables -A INPUT -s 71.6.165.200 -j DROP  # 4 hits
iptables -A INPUT -s 8.211.32.231 -j DROP  # 4 hits
iptables -A INPUT -s 8.216.5.206 -j DROP  # 4 hits
iptables -A INPUT -s 80.82.70.133 -j DROP  # 4 hits
iptables -A INPUT -s 86.54.31.36 -j DROP  # 4 hits
iptables -A INPUT -s 9.234.8.54 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.213 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.28 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.3 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.93 -j DROP  # 4 hits
iptables -A INPUT -s 91.231.89.148 -j DROP  # 4 hits
iptables -A INPUT -s 87.121.84.8 -j DROP  # 3 hits
iptables -A INPUT -s 101.36.109.144 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.209.9 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.52 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.72 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.73 -j DROP  # 3 hits
iptables -A INPUT -s 118.26.104.179 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.165 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.191 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.249 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.202 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.8 -j DROP  # 3 hits
iptables -A INPUT -s 152.32.207.124 -j DROP  # 3 hits
iptables -A INPUT -s 157.230.209.253 -j DROP  # 3 hits
iptables -A INPUT -s 159.223.169.93 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.35 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.72 -j DROP  # 3 hits
iptables -A INPUT -s 165.154.206.223 -j DROP  # 3 hits
iptables -A INPUT -s 165.154.41.205 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.132.93 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.148.197 -j DROP  # 3 hits
iptables -A INPUT -s 178.83.200.2 -j DROP  # 3 hits
iptables -A INPUT -s 180.76.172.156 -j DROP  # 3 hits
iptables -A INPUT -s 185.180.141.33 -j DROP  # 3 hits
iptables -A INPUT -s 185.180.141.35 -j DROP  # 3 hits
iptables -A INPUT -s 185.180.141.42 -j DROP  # 3 hits
iptables -A INPUT -s 185.180.141.43 -j DROP  # 3 hits
iptables -A INPUT -s 185.180.141.45 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.197.10 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.197.33 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.197.37 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.197.39 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.197.40 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.36 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.74 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.91 -j DROP  # 3 hits
iptables -A INPUT -s 185.93.89.192 -j DROP  # 3 hits
iptables -A INPUT -s 194.88.98.84 -j DROP  # 3 hits
iptables -A INPUT -s 195.140.214.19 -j DROP  # 3 hits
iptables -A INPUT -s 195.140.214.25 -j DROP  # 3 hits
iptables -A INPUT -s 195.140.214.26 -j DROP  # 3 hits
iptables -A INPUT -s 195.140.214.30 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.131 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.138 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.171 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.2 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.215 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.229 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.65 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.89 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.94 -j DROP  # 3 hits