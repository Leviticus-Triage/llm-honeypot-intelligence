#!/bin/bash
# LLM Honeypot Intelligence - Firewall Blocklist
# Generated: 2026-02-15 13:49 UTC
# Total: 537 IPs | Blocked: 56 scanners + 136 repeat + 311 active

# Mass Scanners (known infrastructure)
iptables -A INPUT -s 167.94.138.166 -j DROP  # scanner, 9 hits
iptables -A INPUT -s 80.82.77.139 -j DROP  # scanner, 9 hits
iptables -A INPUT -s 167.94.138.48 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 162.142.125.201 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 167.94.138.58 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 167.94.146.54 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 184.105.247.194 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 162.142.125.196 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 162.142.125.40 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 167.94.146.48 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 162.142.125.114 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 162.142.125.204 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 167.94.146.61 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 184.105.139.69 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 74.82.47.4 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 162.142.125.33 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 167.94.146.51 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 162.142.125.35 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 167.94.138.122 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 167.94.138.167 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 167.94.138.170 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 167.94.138.36 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 184.105.139.67 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 184.105.139.68 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 184.105.139.70 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 184.105.247.252 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.102 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.221 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.255 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.226 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 162.142.125.112 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 162.142.125.197 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 162.142.125.213 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 162.142.125.39 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 162.142.125.45 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.116 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.119 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.163 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.169 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.194 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.196 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.32 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.39 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.42 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.45 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.52 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.53 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.138.56 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.49 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.50 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.52 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.55 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 167.94.146.59 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 162.142.125.216 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.42 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 205.210.31.111 -j DROP  # scanner, 1 hits

# Repeat Offenders (>= 10 hits)
iptables -A INPUT -s 38.101.149.7 -j DROP  # 1127371 hits
iptables -A INPUT -s 38.97.63.19 -j DROP  # 849758 hits
iptables -A INPUT -s 38.97.62.53 -j DROP  # 712912 hits
iptables -A INPUT -s 38.97.63.7 -j DROP  # 581295 hits
iptables -A INPUT -s 38.46.220.123 -j DROP  # 532857 hits
iptables -A INPUT -s 165.245.135.196 -j DROP  # 49997 hits
iptables -A INPUT -s 46.19.137.194 -j DROP  # 638 hits
iptables -A INPUT -s 87.120.191.13 -j DROP  # 487 hits
iptables -A INPUT -s 91.238.181.44 -j DROP  # 448 hits
iptables -A INPUT -s 134.209.88.161 -j DROP  # 306 hits
iptables -A INPUT -s 178.62.246.164 -j DROP  # 306 hits
iptables -A INPUT -s 209.38.47.189 -j DROP  # 220 hits
iptables -A INPUT -s 134.209.201.153 -j DROP  # 168 hits
iptables -A INPUT -s 178.62.253.238 -j DROP  # 164 hits
iptables -A INPUT -s 159.223.235.11 -j DROP  # 157 hits
iptables -A INPUT -s 157.245.73.153 -j DROP  # 155 hits
iptables -A INPUT -s 104.248.201.27 -j DROP  # 148 hits
iptables -A INPUT -s 213.32.90.21 -j DROP  # 122 hits
iptables -A INPUT -s 174.138.9.38 -j DROP  # 121 hits
iptables -A INPUT -s 146.190.235.175 -j DROP  # 113 hits
iptables -A INPUT -s 175.144.60.167 -j DROP  # 112 hits
iptables -A INPUT -s 165.232.86.175 -j DROP  # 108 hits
iptables -A INPUT -s 178.128.50.178 -j DROP  # 91 hits
iptables -A INPUT -s 68.183.14.113 -j DROP  # 89 hits
iptables -A INPUT -s 89.42.231.186 -j DROP  # 86 hits
iptables -A INPUT -s 152.42.184.113 -j DROP  # 70 hits
iptables -A INPUT -s 87.120.191.65 -j DROP  # 70 hits
iptables -A INPUT -s 167.99.37.249 -j DROP  # 61 hits
iptables -A INPUT -s 45.148.10.121 -j DROP  # 58 hits
iptables -A INPUT -s 212.11.64.219 -j DROP  # 57 hits
iptables -A INPUT -s 216.180.246.88 -j DROP  # 56 hits
iptables -A INPUT -s 64.227.142.15 -j DROP  # 56 hits
iptables -A INPUT -s 204.76.203.219 -j DROP  # 55 hits
iptables -A INPUT -s 195.3.223.17 -j DROP  # 54 hits
iptables -A INPUT -s 216.180.246.237 -j DROP  # 51 hits
iptables -A INPUT -s 123.190.136.108 -j DROP  # 50 hits
iptables -A INPUT -s 175.107.1.51 -j DROP  # 50 hits
iptables -A INPUT -s 185.243.5.46 -j DROP  # 49 hits
iptables -A INPUT -s 68.183.94.127 -j DROP  # 49 hits
iptables -A INPUT -s 45.194.92.199 -j DROP  # 48 hits
iptables -A INPUT -s 188.166.72.154 -j DROP  # 47 hits
iptables -A INPUT -s 92.118.39.76 -j DROP  # 43 hits
iptables -A INPUT -s 143.198.194.63 -j DROP  # 42 hits
iptables -A INPUT -s 157.245.97.16 -j DROP  # 42 hits
iptables -A INPUT -s 159.223.209.75 -j DROP  # 42 hits
iptables -A INPUT -s 173.255.204.184 -j DROP  # 39 hits
iptables -A INPUT -s 81.29.142.6 -j DROP  # 38 hits
iptables -A INPUT -s 14.1.105.20 -j DROP  # 38 hits
iptables -A INPUT -s 216.180.246.81 -j DROP  # 38 hits
iptables -A INPUT -s 195.3.221.8 -j DROP  # 37 hits
iptables -A INPUT -s 182.117.172.215 -j DROP  # 37 hits
iptables -A INPUT -s 216.180.246.196 -j DROP  # 37 hits
iptables -A INPUT -s 79.124.59.78 -j DROP  # 37 hits
iptables -A INPUT -s 204.76.203.18 -j DROP  # 35 hits
iptables -A INPUT -s 77.90.185.18 -j DROP  # 34 hits
iptables -A INPUT -s 216.180.246.118 -j DROP  # 33 hits
iptables -A INPUT -s 216.180.246.132 -j DROP  # 33 hits
iptables -A INPUT -s 216.180.246.170 -j DROP  # 33 hits
iptables -A INPUT -s 216.180.246.219 -j DROP  # 33 hits
iptables -A INPUT -s 216.180.246.221 -j DROP  # 33 hits
iptables -A INPUT -s 216.180.246.55 -j DROP  # 33 hits
iptables -A INPUT -s 216.180.246.87 -j DROP  # 33 hits
iptables -A INPUT -s 159.65.230.215 -j DROP  # 31 hits
iptables -A INPUT -s 182.127.71.46 -j DROP  # 30 hits
iptables -A INPUT -s 45.135.193.11 -j DROP  # 29 hits
iptables -A INPUT -s 130.12.180.51 -j DROP  # 29 hits
iptables -A INPUT -s 216.180.246.38 -j DROP  # 29 hits
iptables -A INPUT -s 209.38.43.38 -j DROP  # 28 hits
iptables -A INPUT -s 80.94.92.171 -j DROP  # 28 hits
iptables -A INPUT -s 3.129.187.38 -j DROP  # 28 hits
iptables -A INPUT -s 45.82.78.102 -j DROP  # 28 hits
iptables -A INPUT -s 216.180.246.227 -j DROP  # 26 hits
iptables -A INPUT -s 45.82.78.105 -j DROP  # 26 hits
iptables -A INPUT -s 152.42.132.197 -j DROP  # 25 hits
iptables -A INPUT -s 45.82.78.103 -j DROP  # 25 hits
iptables -A INPUT -s 103.174.103.249 -j DROP  # 23 hits
iptables -A INPUT -s 18.116.101.220 -j DROP  # 23 hits
iptables -A INPUT -s 45.91.64.6 -j DROP  # 23 hits
iptables -A INPUT -s 91.92.241.59 -j DROP  # 23 hits
iptables -A INPUT -s 108.244.10.156 -j DROP  # 22 hits
iptables -A INPUT -s 129.146.125.96 -j DROP  # 22 hits
iptables -A INPUT -s 170.39.218.48 -j DROP  # 22 hits
iptables -A INPUT -s 216.180.246.160 -j DROP  # 22 hits
iptables -A INPUT -s 66.167.147.130 -j DROP  # 22 hits
iptables -A INPUT -s 18.218.118.203 -j DROP  # 21 hits
iptables -A INPUT -s 216.180.246.200 -j DROP  # 21 hits
iptables -A INPUT -s 45.82.78.108 -j DROP  # 21 hits
iptables -A INPUT -s 195.3.221.86 -j DROP  # 19 hits
iptables -A INPUT -s 216.180.246.243 -j DROP  # 19 hits
iptables -A INPUT -s 216.180.246.6 -j DROP  # 19 hits
iptables -A INPUT -s 146.190.17.130 -j DROP  # 18 hits
iptables -A INPUT -s 178.128.248.242 -j DROP  # 18 hits
iptables -A INPUT -s 216.180.246.161 -j DROP  # 18 hits
iptables -A INPUT -s 216.180.246.223 -j DROP  # 18 hits
iptables -A INPUT -s 216.180.246.50 -j DROP  # 18 hits
iptables -A INPUT -s 87.106.146.117 -j DROP  # 17 hits
iptables -A INPUT -s 68.183.0.4 -j DROP  # 16 hits
iptables -A INPUT -s 216.180.246.144 -j DROP  # 16 hits
iptables -A INPUT -s 95.214.52.233 -j DROP  # 16 hits
iptables -A INPUT -s 204.76.203.206 -j DROP  # 15 hits
iptables -A INPUT -s 45.153.34.187 -j DROP  # 15 hits
iptables -A INPUT -s 204.76.203.69 -j DROP  # 15 hits
iptables -A INPUT -s 87.120.191.81 -j DROP  # 15 hits
iptables -A INPUT -s 118.194.236.137 -j DROP  # 15 hits
iptables -A INPUT -s 193.142.146.230 -j DROP  # 15 hits
iptables -A INPUT -s 217.216.40.246 -j DROP  # 15 hits
iptables -A INPUT -s 45.142.154.15 -j DROP  # 15 hits
iptables -A INPUT -s 47.253.183.81 -j DROP  # 15 hits
iptables -A INPUT -s 51.159.110.167 -j DROP  # 15 hits
iptables -A INPUT -s 87.120.191.67 -j DROP  # 14 hits
iptables -A INPUT -s 64.227.167.126 -j DROP  # 14 hits
iptables -A INPUT -s 80.66.83.43 -j DROP  # 14 hits
iptables -A INPUT -s 89.42.231.184 -j DROP  # 14 hits
iptables -A INPUT -s 66.132.153.125 -j DROP  # 13 hits
iptables -A INPUT -s 165.154.138.79 -j DROP  # 12 hits
iptables -A INPUT -s 178.128.66.56 -j DROP  # 12 hits
iptables -A INPUT -s 185.224.128.16 -j DROP  # 12 hits
iptables -A INPUT -s 71.6.158.166 -j DROP  # 12 hits
iptables -A INPUT -s 130.12.180.55 -j DROP  # 11 hits
iptables -A INPUT -s 204.76.203.56 -j DROP  # 11 hits
iptables -A INPUT -s 3.131.220.121 -j DROP  # 11 hits
iptables -A INPUT -s 65.49.20.68 -j DROP  # 11 hits
iptables -A INPUT -s 161.35.94.184 -j DROP  # 10 hits
iptables -A INPUT -s 34.158.168.101 -j DROP  # 10 hits
iptables -A INPUT -s 104.248.242.212 -j DROP  # 10 hits
iptables -A INPUT -s 118.193.40.131 -j DROP  # 10 hits
iptables -A INPUT -s 123.234.81.180 -j DROP  # 10 hits
iptables -A INPUT -s 13.86.116.129 -j DROP  # 10 hits
iptables -A INPUT -s 192.227.159.123 -j DROP  # 10 hits
iptables -A INPUT -s 216.180.246.106 -j DROP  # 10 hits
iptables -A INPUT -s 44.220.188.211 -j DROP  # 10 hits
iptables -A INPUT -s 45.142.154.31 -j DROP  # 10 hits
iptables -A INPUT -s 45.156.87.205 -j DROP  # 10 hits
iptables -A INPUT -s 64.225.34.171 -j DROP  # 10 hits
iptables -A INPUT -s 83.246.248.9 -j DROP  # 10 hits
iptables -A INPUT -s 86.54.31.44 -j DROP  # 10 hits

# Active Attackers (>= 3 hits)
iptables -A INPUT -s 155.4.119.66 -j DROP  # 9 hits
iptables -A INPUT -s 81.29.142.100 -j DROP  # 9 hits
iptables -A INPUT -s 147.182.169.249 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.134.182 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.159.177 -j DROP  # 9 hits
iptables -A INPUT -s 165.154.138.57 -j DROP  # 9 hits
iptables -A INPUT -s 176.65.148.57 -j DROP  # 9 hits
iptables -A INPUT -s 185.242.226.10 -j DROP  # 9 hits
iptables -A INPUT -s 43.204.120.120 -j DROP  # 9 hits
iptables -A INPUT -s 64.62.197.107 -j DROP  # 9 hits
iptables -A INPUT -s 64.62.197.182 -j DROP  # 9 hits
iptables -A INPUT -s 118.193.59.194 -j DROP  # 8 hits
iptables -A INPUT -s 118.194.250.2 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.128.149 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.128.169 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.140.12 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.150.29 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.156.117 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.164.139 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.181.210 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.206.246 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.207.21 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.216.28 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.227.68 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.235.206 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.235.90 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.11.172 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.12.139 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.138.34 -j DROP  # 8 hits
iptables -A INPUT -s 185.242.226.73 -j DROP  # 8 hits
iptables -A INPUT -s 204.76.203.73 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.100 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.106 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.107 -j DROP  # 8 hits
iptables -A INPUT -s 47.250.153.30 -j DROP  # 8 hits
iptables -A INPUT -s 64.225.77.60 -j DROP  # 8 hits
iptables -A INPUT -s 66.175.213.4 -j DROP  # 8 hits
iptables -A INPUT -s 86.54.31.32 -j DROP  # 8 hits
iptables -A INPUT -s 3.130.168.2 -j DROP  # 7 hits
iptables -A INPUT -s 103.203.58.4 -j DROP  # 7 hits
iptables -A INPUT -s 104.218.165.188 -j DROP  # 7 hits
iptables -A INPUT -s 106.75.11.183 -j DROP  # 7 hits
iptables -A INPUT -s 118.193.65.209 -j DROP  # 7 hits
iptables -A INPUT -s 118.194.238.196 -j DROP  # 7 hits
iptables -A INPUT -s 118.194.251.141 -j DROP  # 7 hits
iptables -A INPUT -s 123.58.207.151 -j DROP  # 7 hits
iptables -A INPUT -s 128.1.46.183 -j DROP  # 7 hits
iptables -A INPUT -s 128.14.236.128 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.149.47 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.180.138 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.235.96 -j DROP  # 7 hits
iptables -A INPUT -s 162.216.150.250 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.104.235 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.128.17 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.174.206 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.221.151 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.33.91 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.48.24 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.58.108 -j DROP  # 7 hits
iptables -A INPUT -s 165.154.58.251 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.19.149 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.5.101 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.5.43 -j DROP  # 7 hits
iptables -A INPUT -s 195.178.136.18 -j DROP  # 7 hits
iptables -A INPUT -s 216.180.246.139 -j DROP  # 7 hits
iptables -A INPUT -s 35.203.210.22 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.183 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.25 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.78 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.63 -j DROP  # 7 hits
iptables -A INPUT -s 45.142.154.96 -j DROP  # 7 hits
iptables -A INPUT -s 45.82.78.104 -j DROP  # 7 hits
iptables -A INPUT -s 65.49.1.182 -j DROP  # 7 hits
iptables -A INPUT -s 65.49.20.69 -j DROP  # 7 hits
iptables -A INPUT -s 98.80.4.100 -j DROP  # 7 hits
iptables -A INPUT -s 103.148.195.198 -j DROP  # 6 hits
iptables -A INPUT -s 89.42.231.200 -j DROP  # 6 hits
iptables -A INPUT -s 103.16.31.250 -j DROP  # 6 hits
iptables -A INPUT -s 106.75.9.106 -j DROP  # 6 hits
iptables -A INPUT -s 154.197.56.163 -j DROP  # 6 hits
iptables -A INPUT -s 18.97.19.225 -j DROP  # 6 hits
iptables -A INPUT -s 18.97.26.44 -j DROP  # 6 hits
iptables -A INPUT -s 185.180.141.43 -j DROP  # 6 hits
iptables -A INPUT -s 185.226.197.13 -j DROP  # 6 hits
iptables -A INPUT -s 185.242.226.104 -j DROP  # 6 hits
iptables -A INPUT -s 20.119.74.72 -j DROP  # 6 hits
iptables -A INPUT -s 204.76.203.215 -j DROP  # 6 hits
iptables -A INPUT -s 206.168.34.112 -j DROP  # 6 hits
iptables -A INPUT -s 206.168.34.42 -j DROP  # 6 hits
iptables -A INPUT -s 207.90.244.12 -j DROP  # 6 hits
iptables -A INPUT -s 216.180.246.173 -j DROP  # 6 hits
iptables -A INPUT -s 216.180.246.199 -j DROP  # 6 hits
iptables -A INPUT -s 216.180.246.231 -j DROP  # 6 hits
iptables -A INPUT -s 216.180.246.65 -j DROP  # 6 hits
iptables -A INPUT -s 35.203.211.182 -j DROP  # 6 hits
iptables -A INPUT -s 45.142.154.12 -j DROP  # 6 hits
iptables -A INPUT -s 64.62.156.162 -j DROP  # 6 hits
iptables -A INPUT -s 64.62.156.172 -j DROP  # 6 hits
iptables -A INPUT -s 64.62.197.227 -j DROP  # 6 hits
iptables -A INPUT -s 85.11.167.104 -j DROP  # 6 hits
iptables -A INPUT -s 176.65.134.3 -j DROP  # 5 hits
iptables -A INPUT -s 35.205.235.254 -j DROP  # 5 hits
iptables -A INPUT -s 101.36.108.184 -j DROP  # 5 hits
iptables -A INPUT -s 106.75.2.130 -j DROP  # 5 hits
iptables -A INPUT -s 118.193.33.104 -j DROP  # 5 hits
iptables -A INPUT -s 147.185.133.161 -j DROP  # 5 hits
iptables -A INPUT -s 147.185.133.27 -j DROP  # 5 hits
iptables -A INPUT -s 150.107.38.251 -j DROP  # 5 hits
iptables -A INPUT -s 152.32.216.8 -j DROP  # 5 hits
iptables -A INPUT -s 162.216.149.170 -j DROP  # 5 hits
iptables -A INPUT -s 162.216.149.227 -j DROP  # 5 hits
iptables -A INPUT -s 162.216.149.238 -j DROP  # 5 hits
iptables -A INPUT -s 162.216.149.31 -j DROP  # 5 hits
iptables -A INPUT -s 162.216.149.6 -j DROP  # 5 hits
iptables -A INPUT -s 162.216.150.111 -j DROP  # 5 hits
iptables -A INPUT -s 162.216.150.192 -j DROP  # 5 hits
iptables -A INPUT -s 176.65.139.19 -j DROP  # 5 hits
iptables -A INPUT -s 183.56.243.176 -j DROP  # 5 hits
iptables -A INPUT -s 20.65.136.30 -j DROP  # 5 hits
iptables -A INPUT -s 206.168.34.33 -j DROP  # 5 hits
iptables -A INPUT -s 206.168.34.58 -j DROP  # 5 hits
iptables -A INPUT -s 216.180.246.246 -j DROP  # 5 hits
iptables -A INPUT -s 216.218.206.68 -j DROP  # 5 hits
iptables -A INPUT -s 35.203.210.160 -j DROP  # 5 hits
iptables -A INPUT -s 35.203.210.162 -j DROP  # 5 hits
iptables -A INPUT -s 35.203.210.166 -j DROP  # 5 hits
iptables -A INPUT -s 35.203.210.180 -j DROP  # 5 hits
iptables -A INPUT -s 35.203.210.241 -j DROP  # 5 hits
iptables -A INPUT -s 35.203.210.252 -j DROP  # 5 hits
iptables -A INPUT -s 35.203.210.88 -j DROP  # 5 hits
iptables -A INPUT -s 36.255.223.187 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.185.235 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.188.170 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.114 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.18 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.37 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.38 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.42 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.43 -j DROP  # 5 hits
iptables -A INPUT -s 45.249.246.82 -j DROP  # 5 hits
iptables -A INPUT -s 47.250.123.240 -j DROP  # 5 hits
iptables -A INPUT -s 47.84.179.64 -j DROP  # 5 hits
iptables -A INPUT -s 47.84.196.3 -j DROP  # 5 hits
iptables -A INPUT -s 47.84.199.84 -j DROP  # 5 hits
iptables -A INPUT -s 64.62.156.182 -j DROP  # 5 hits
iptables -A INPUT -s 65.49.1.152 -j DROP  # 5 hits
iptables -A INPUT -s 65.49.1.192 -j DROP  # 5 hits
iptables -A INPUT -s 65.49.1.38 -j DROP  # 5 hits
iptables -A INPUT -s 8.138.219.65 -j DROP  # 5 hits
iptables -A INPUT -s 176.65.132.94 -j DROP  # 4 hits
iptables -A INPUT -s 195.178.110.241 -j DROP  # 4 hits
iptables -A INPUT -s 176.65.148.203 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.156.108 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.156.52 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.209.32 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.210.52 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.210.72 -j DROP  # 4 hits
iptables -A INPUT -s 13.89.125.254 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.139 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.191 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.133.130 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.133.166 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.133.185 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.133.237 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.133.78 -j DROP  # 4 hits
iptables -A INPUT -s 148.153.188.246 -j DROP  # 4 hits
iptables -A INPUT -s 158.94.211.102 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.149.113 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.149.122 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.149.166 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.149.246 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.149.26 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.149.30 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.149.63 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.149.86 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.113 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.114 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.153 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.194 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.204 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.208 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.215 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.217 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.23 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.245 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.26 -j DROP  # 4 hits
iptables -A INPUT -s 162.216.150.40 -j DROP  # 4 hits
iptables -A INPUT -s 165.154.41.97 -j DROP  # 4 hits
iptables -A INPUT -s 165.154.51.193 -j DROP  # 4 hits
iptables -A INPUT -s 176.32.195.85 -j DROP  # 4 hits
iptables -A INPUT -s 188.166.23.226 -j DROP  # 4 hits
iptables -A INPUT -s 20.14.73.62 -j DROP  # 4 hits
iptables -A INPUT -s 20.15.160.31 -j DROP  # 4 hits
iptables -A INPUT -s 206.168.34.118 -j DROP  # 4 hits
iptables -A INPUT -s 206.168.34.194 -j DROP  # 4 hits
iptables -A INPUT -s 206.168.34.50 -j DROP  # 4 hits
iptables -A INPUT -s 216.180.246.128 -j DROP  # 4 hits
iptables -A INPUT -s 216.180.246.217 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.210.127 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.210.150 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.210.173 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.210.205 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.210.55 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.210.89 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.211.162 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.211.173 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.211.181 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.211.243 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.211.40 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.211.50 -j DROP  # 4 hits
iptables -A INPUT -s 36.32.200.194 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.129.81 -j DROP  # 4 hits
iptables -A INPUT -s 47.236.248.96 -j DROP  # 4 hits
iptables -A INPUT -s 47.250.182.96 -j DROP  # 4 hits
iptables -A INPUT -s 47.250.52.225 -j DROP  # 4 hits
iptables -A INPUT -s 47.251.165.41 -j DROP  # 4 hits
iptables -A INPUT -s 47.254.193.39 -j DROP  # 4 hits
iptables -A INPUT -s 47.77.228.106 -j DROP  # 4 hits
iptables -A INPUT -s 60.191.137.103 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.156.10 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.156.152 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.197.137 -j DROP  # 4 hits
iptables -A INPUT -s 65.49.1.142 -j DROP  # 4 hits
iptables -A INPUT -s 65.49.1.66 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.153.120 -j DROP  # 4 hits
iptables -A INPUT -s 71.6.165.200 -j DROP  # 4 hits
iptables -A INPUT -s 86.54.31.36 -j DROP  # 4 hits
iptables -A INPUT -s 87.121.84.88 -j DROP  # 4 hits
iptables -A INPUT -s 89.248.167.131 -j DROP  # 4 hits
iptables -A INPUT -s 94.231.206.111 -j DROP  # 4 hits
iptables -A INPUT -s 95.111.241.165 -j DROP  # 4 hits
iptables -A INPUT -s 176.65.134.20 -j DROP  # 3 hits
iptables -A INPUT -s 27.0.232.228 -j DROP  # 3 hits
iptables -A INPUT -s 77.42.23.122 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.149.17 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.209.35 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.55 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.74 -j DROP  # 3 hits
iptables -A INPUT -s 109.105.210.75 -j DROP  # 3 hits
iptables -A INPUT -s 114.220.75.156 -j DROP  # 3 hits
iptables -A INPUT -s 120.48.45.123 -j DROP  # 3 hits
iptables -A INPUT -s 128.203.200.49 -j DROP  # 3 hits
iptables -A INPUT -s 134.209.2.113 -j DROP  # 3 hits
iptables -A INPUT -s 138.68.253.225 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.130 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.149 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.170 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.18 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.223 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.24 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.46 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.57 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.61 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.68 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.73 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.89 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.9 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.98 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.106 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.110 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.12 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.145 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.157 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.162 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.169 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.198 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.212 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.234 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.24 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.98 -j DROP  # 3 hits
iptables -A INPUT -s 157.230.12.54 -j DROP  # 3 hits
iptables -A INPUT -s 161.35.100.188 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.12 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.16 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.165 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.182 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.192 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.200 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.28 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.44 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.47 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.5 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.73 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.78 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.9 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.99 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.148 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.163 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.186 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.253 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.34 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.50 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.6 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.60 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.64 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.9 -j DROP  # 3 hits
iptables -A INPUT -s 165.154.163.10 -j DROP  # 3 hits
iptables -A INPUT -s 165.154.173.141 -j DROP  # 3 hits
iptables -A INPUT -s 167.71.119.70 -j DROP  # 3 hits
iptables -A INPUT -s 173.230.155.91 -j DROP  # 3 hits
iptables -A INPUT -s 173.255.204.57 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.134.34 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.139.8 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.148.95 -j DROP  # 3 hits
iptables -A INPUT -s 178.83.200.2 -j DROP  # 3 hits
iptables -A INPUT -s 185.114.175.11 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.17 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.33 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.36 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.59 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.90 -j DROP  # 3 hits