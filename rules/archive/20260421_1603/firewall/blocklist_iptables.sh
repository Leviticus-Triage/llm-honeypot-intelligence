#!/bin/bash
# LLM Honeypot Intelligence - Firewall Blocklist
# Generated: 2026-04-21 16:03 UTC
# Total: 547 IPs | Blocked: 43 scanners + 197 repeat + 260 active

# Mass Scanners (known infrastructure)
iptables -A INPUT -s 167.94.146.62 -j DROP  # scanner, 12 hits
iptables -A INPUT -s 167.94.146.48 -j DROP  # scanner, 11 hits
iptables -A INPUT -s 167.94.146.57 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 167.94.146.50 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 167.94.146.53 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 167.94.146.60 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 184.105.139.68 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 167.94.146.54 -j DROP  # scanner, 9 hits
iptables -A INPUT -s 167.94.146.51 -j DROP  # scanner, 9 hits
iptables -A INPUT -s 167.94.146.61 -j DROP  # scanner, 9 hits
iptables -A INPUT -s 184.105.247.196 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.56 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.59 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.49 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 167.94.146.58 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 71.6.147.254 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 167.94.146.63 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 184.105.139.67 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 198.235.24.203 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 205.210.31.224 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 205.210.31.85 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 167.94.146.52 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 167.94.146.55 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 184.105.247.195 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.108 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.116 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.217 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.65 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.68 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.98 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.153 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 184.105.247.252 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.174 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.255 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.54 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.167 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.219 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.222 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.241 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.248 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.77 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.60 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 205.210.31.83 -j DROP  # scanner, 1 hits

# Repeat Offenders (>= 10 hits)
iptables -A INPUT -s 176.65.139.103 -j DROP  # 9062 hits
iptables -A INPUT -s 104.243.32.126 -j DROP  # 4833 hits
iptables -A INPUT -s 104.243.35.94 -j DROP  # 3257 hits
iptables -A INPUT -s 104.243.35.92 -j DROP  # 2273 hits
iptables -A INPUT -s 104.243.32.235 -j DROP  # 2015 hits
iptables -A INPUT -s 177.125.137.18 -j DROP  # 1849 hits
iptables -A INPUT -s 51.68.207.118 -j DROP  # 1549 hits
iptables -A INPUT -s 104.243.43.7 -j DROP  # 1499 hits
iptables -A INPUT -s 45.156.87.99 -j DROP  # 1370 hits
iptables -A INPUT -s 165.227.156.190 -j DROP  # 1266 hits
iptables -A INPUT -s 209.38.95.158 -j DROP  # 1266 hits
iptables -A INPUT -s 87.251.64.159 -j DROP  # 1265 hits
iptables -A INPUT -s 64.227.186.247 -j DROP  # 1263 hits
iptables -A INPUT -s 68.183.77.93 -j DROP  # 1263 hits
iptables -A INPUT -s 142.93.222.251 -j DROP  # 1261 hits
iptables -A INPUT -s 167.172.175.156 -j DROP  # 1260 hits
iptables -A INPUT -s 206.221.176.60 -j DROP  # 1260 hits
iptables -A INPUT -s 85.11.167.11 -j DROP  # 1092 hits
iptables -A INPUT -s 104.243.34.165 -j DROP  # 1088 hits
iptables -A INPUT -s 170.64.177.137 -j DROP  # 643 hits
iptables -A INPUT -s 185.150.191.236 -j DROP  # 486 hits
iptables -A INPUT -s 104.243.35.104 -j DROP  # 449 hits
iptables -A INPUT -s 185.150.191.165 -j DROP  # 430 hits
iptables -A INPUT -s 104.243.35.120 -j DROP  # 383 hits
iptables -A INPUT -s 185.91.127.85 -j DROP  # 252 hits
iptables -A INPUT -s 209.222.101.194 -j DROP  # 220 hits
iptables -A INPUT -s 104.243.43.19 -j DROP  # 215 hits
iptables -A INPUT -s 45.205.1.5 -j DROP  # 197 hits
iptables -A INPUT -s 45.205.1.110 -j DROP  # 172 hits
iptables -A INPUT -s 220.92.117.221 -j DROP  # 159 hits
iptables -A INPUT -s 18.218.118.203 -j DROP  # 155 hits
iptables -A INPUT -s 3.129.187.38 -j DROP  # 154 hits
iptables -A INPUT -s 31.148.197.148 -j DROP  # 150 hits
iptables -A INPUT -s 2.57.122.238 -j DROP  # 143 hits
iptables -A INPUT -s 16.58.56.214 -j DROP  # 128 hits
iptables -A INPUT -s 18.116.101.220 -j DROP  # 127 hits
iptables -A INPUT -s 80.66.83.43 -j DROP  # 123 hits
iptables -A INPUT -s 3.130.168.2 -j DROP  # 119 hits
iptables -A INPUT -s 85.217.140.28 -j DROP  # 113 hits
iptables -A INPUT -s 178.128.156.201 -j DROP  # 111 hits
iptables -A INPUT -s 152.42.238.0 -j DROP  # 105 hits
iptables -A INPUT -s 3.131.220.121 -j DROP  # 91 hits
iptables -A INPUT -s 93.123.72.166 -j DROP  # 88 hits
iptables -A INPUT -s 81.29.142.100 -j DROP  # 82 hits
iptables -A INPUT -s 103.156.20.188 -j DROP  # 70 hits
iptables -A INPUT -s 5.29.10.22 -j DROP  # 60 hits
iptables -A INPUT -s 46.151.178.13 -j DROP  # 58 hits
iptables -A INPUT -s 92.63.197.22 -j DROP  # 56 hits
iptables -A INPUT -s 193.176.31.150 -j DROP  # 52 hits
iptables -A INPUT -s 200.124.160.2 -j DROP  # 52 hits
iptables -A INPUT -s 206.189.185.96 -j DROP  # 51 hits
iptables -A INPUT -s 103.18.14.52 -j DROP  # 50 hits
iptables -A INPUT -s 103.244.172.34 -j DROP  # 50 hits
iptables -A INPUT -s 175.107.2.111 -j DROP  # 50 hits
iptables -A INPUT -s 194.88.98.89 -j DROP  # 50 hits
iptables -A INPUT -s 193.124.20.245 -j DROP  # 49 hits
iptables -A INPUT -s 45.205.1.26 -j DROP  # 49 hits
iptables -A INPUT -s 85.217.140.32 -j DROP  # 49 hits
iptables -A INPUT -s 194.88.98.84 -j DROP  # 48 hits
iptables -A INPUT -s 223.123.73.191 -j DROP  # 46 hits
iptables -A INPUT -s 42.231.38.235 -j DROP  # 46 hits
iptables -A INPUT -s 3.151.241.153 -j DROP  # 45 hits
iptables -A INPUT -s 195.140.214.27 -j DROP  # 45 hits
iptables -A INPUT -s 37.10.113.212 -j DROP  # 44 hits
iptables -A INPUT -s 37.10.113.213 -j DROP  # 44 hits
iptables -A INPUT -s 193.176.31.154 -j DROP  # 43 hits
iptables -A INPUT -s 193.124.20.253 -j DROP  # 43 hits
iptables -A INPUT -s 193.176.31.148 -j DROP  # 43 hits
iptables -A INPUT -s 193.176.31.158 -j DROP  # 43 hits
iptables -A INPUT -s 37.10.113.211 -j DROP  # 43 hits
iptables -A INPUT -s 193.124.20.251 -j DROP  # 42 hits
iptables -A INPUT -s 194.88.98.86 -j DROP  # 42 hits
iptables -A INPUT -s 194.88.98.90 -j DROP  # 42 hits
iptables -A INPUT -s 37.10.113.216 -j DROP  # 42 hits
iptables -A INPUT -s 80.94.95.110 -j DROP  # 42 hits
iptables -A INPUT -s 193.176.31.152 -j DROP  # 41 hits
iptables -A INPUT -s 3.143.162.210 -j DROP  # 41 hits
iptables -A INPUT -s 37.10.113.217 -j DROP  # 41 hits
iptables -A INPUT -s 80.94.95.88 -j DROP  # 41 hits
iptables -A INPUT -s 194.88.98.94 -j DROP  # 40 hits
iptables -A INPUT -s 193.124.20.252 -j DROP  # 40 hits
iptables -A INPUT -s 3.134.216.108 -j DROP  # 40 hits
iptables -A INPUT -s 80.94.92.182 -j DROP  # 40 hits
iptables -A INPUT -s 85.217.140.46 -j DROP  # 40 hits
iptables -A INPUT -s 37.10.113.215 -j DROP  # 39 hits
iptables -A INPUT -s 193.124.20.244 -j DROP  # 38 hits
iptables -A INPUT -s 194.88.98.83 -j DROP  # 38 hits
iptables -A INPUT -s 37.10.113.218 -j DROP  # 38 hits
iptables -A INPUT -s 37.10.113.220 -j DROP  # 38 hits
iptables -A INPUT -s 92.38.148.36 -j DROP  # 38 hits
iptables -A INPUT -s 193.124.20.246 -j DROP  # 37 hits
iptables -A INPUT -s 193.176.31.155 -j DROP  # 37 hits
iptables -A INPUT -s 193.176.31.157 -j DROP  # 37 hits
iptables -A INPUT -s 194.88.98.92 -j DROP  # 37 hits
iptables -A INPUT -s 195.140.214.22 -j DROP  # 37 hits
iptables -A INPUT -s 37.10.113.219 -j DROP  # 37 hits
iptables -A INPUT -s 37.10.113.221 -j DROP  # 37 hits
iptables -A INPUT -s 37.10.113.222 -j DROP  # 37 hits
iptables -A INPUT -s 193.124.20.243 -j DROP  # 36 hits
iptables -A INPUT -s 193.124.20.248 -j DROP  # 36 hits
iptables -A INPUT -s 194.88.98.93 -j DROP  # 36 hits
iptables -A INPUT -s 195.140.214.25 -j DROP  # 36 hits
iptables -A INPUT -s 45.82.78.102 -j DROP  # 36 hits
iptables -A INPUT -s 45.82.78.106 -j DROP  # 36 hits
iptables -A INPUT -s 152.53.81.25 -j DROP  # 35 hits
iptables -A INPUT -s 193.124.20.249 -j DROP  # 35 hits
iptables -A INPUT -s 193.176.31.153 -j DROP  # 35 hits
iptables -A INPUT -s 194.88.98.87 -j DROP  # 35 hits
iptables -A INPUT -s 193.124.20.247 -j DROP  # 34 hits
iptables -A INPUT -s 193.124.20.254 -j DROP  # 34 hits
iptables -A INPUT -s 193.176.31.156 -j DROP  # 34 hits
iptables -A INPUT -s 85.11.167.2 -j DROP  # 34 hits
iptables -A INPUT -s 193.124.20.250 -j DROP  # 33 hits
iptables -A INPUT -s 193.176.31.151 -j DROP  # 33 hits
iptables -A INPUT -s 195.140.214.21 -j DROP  # 33 hits
iptables -A INPUT -s 157.230.190.169 -j DROP  # 32 hits
iptables -A INPUT -s 195.140.214.23 -j DROP  # 32 hits
iptables -A INPUT -s 37.10.113.214 -j DROP  # 32 hits
iptables -A INPUT -s 45.82.78.104 -j DROP  # 32 hits
iptables -A INPUT -s 193.176.31.149 -j DROP  # 31 hits
iptables -A INPUT -s 194.88.98.88 -j DROP  # 31 hits
iptables -A INPUT -s 194.88.98.91 -j DROP  # 31 hits
iptables -A INPUT -s 193.176.31.147 -j DROP  # 30 hits
iptables -A INPUT -s 195.140.214.19 -j DROP  # 30 hits
iptables -A INPUT -s 223.123.38.36 -j DROP  # 30 hits
iptables -A INPUT -s 194.88.98.85 -j DROP  # 29 hits
iptables -A INPUT -s 195.140.214.20 -j DROP  # 29 hits
iptables -A INPUT -s 195.140.214.30 -j DROP  # 29 hits
iptables -A INPUT -s 195.140.214.24 -j DROP  # 28 hits
iptables -A INPUT -s 36.255.33.156 -j DROP  # 28 hits
iptables -A INPUT -s 45.82.78.107 -j DROP  # 28 hits
iptables -A INPUT -s 195.140.214.26 -j DROP  # 27 hits
iptables -A INPUT -s 45.148.10.183 -j DROP  # 27 hits
iptables -A INPUT -s 195.140.214.29 -j DROP  # 26 hits
iptables -A INPUT -s 222.223.177.118 -j DROP  # 26 hits
iptables -A INPUT -s 45.142.193.6 -j DROP  # 26 hits
iptables -A INPUT -s 185.224.128.16 -j DROP  # 24 hits
iptables -A INPUT -s 3.132.26.232 -j DROP  # 24 hits
iptables -A INPUT -s 79.124.59.78 -j DROP  # 24 hits
iptables -A INPUT -s 80.66.83.80 -j DROP  # 24 hits
iptables -A INPUT -s 31.56.209.39 -j DROP  # 23 hits
iptables -A INPUT -s 62.164.177.41 -j DROP  # 23 hits
iptables -A INPUT -s 143.20.97.9 -j DROP  # 22 hits
iptables -A INPUT -s 47.94.96.33 -j DROP  # 22 hits
iptables -A INPUT -s 51.158.205.203 -j DROP  # 22 hits
iptables -A INPUT -s 18.225.10.29 -j DROP  # 21 hits
iptables -A INPUT -s 195.140.214.28 -j DROP  # 20 hits
iptables -A INPUT -s 43.226.36.171 -j DROP  # 20 hits
iptables -A INPUT -s 45.135.194.113 -j DROP  # 20 hits
iptables -A INPUT -s 45.82.13.133 -j DROP  # 20 hits
iptables -A INPUT -s 45.82.78.105 -j DROP  # 20 hits
iptables -A INPUT -s 45.82.78.108 -j DROP  # 20 hits
iptables -A INPUT -s 5.187.35.26 -j DROP  # 19 hits
iptables -A INPUT -s 95.214.52.233 -j DROP  # 19 hits
iptables -A INPUT -s 103.117.160.144 -j DROP  # 18 hits
iptables -A INPUT -s 123.11.8.158 -j DROP  # 18 hits
iptables -A INPUT -s 207.90.244.12 -j DROP  # 18 hits
iptables -A INPUT -s 152.32.198.210 -j DROP  # 17 hits
iptables -A INPUT -s 177.76.169.62 -j DROP  # 17 hits
iptables -A INPUT -s 118.193.64.188 -j DROP  # 16 hits
iptables -A INPUT -s 5.187.35.142 -j DROP  # 16 hits
iptables -A INPUT -s 61.156.218.5 -j DROP  # 16 hits
iptables -A INPUT -s 85.217.140.8 -j DROP  # 16 hits
iptables -A INPUT -s 1.95.60.65 -j DROP  # 15 hits
iptables -A INPUT -s 112.47.128.74 -j DROP  # 15 hits
iptables -A INPUT -s 141.98.10.164 -j DROP  # 15 hits
iptables -A INPUT -s 152.32.156.158 -j DROP  # 15 hits
iptables -A INPUT -s 170.39.218.48 -j DROP  # 15 hits
iptables -A INPUT -s 193.142.146.230 -j DROP  # 15 hits
iptables -A INPUT -s 130.12.180.51 -j DROP  # 14 hits
iptables -A INPUT -s 161.35.116.145 -j DROP  # 14 hits
iptables -A INPUT -s 66.132.172.213 -j DROP  # 14 hits
iptables -A INPUT -s 45.82.78.100 -j DROP  # 13 hits
iptables -A INPUT -s 124.198.131.185 -j DROP  # 13 hits
iptables -A INPUT -s 206.189.133.35 -j DROP  # 13 hits
iptables -A INPUT -s 130.12.180.174 -j DROP  # 12 hits
iptables -A INPUT -s 152.32.223.215 -j DROP  # 12 hits
iptables -A INPUT -s 185.242.226.10 -j DROP  # 12 hits
iptables -A INPUT -s 204.76.203.56 -j DROP  # 12 hits
iptables -A INPUT -s 45.148.10.121 -j DROP  # 12 hits
iptables -A INPUT -s 51.159.110.167 -j DROP  # 12 hits
iptables -A INPUT -s 165.154.138.79 -j DROP  # 11 hits
iptables -A INPUT -s 165.154.164.57 -j DROP  # 11 hits
iptables -A INPUT -s 221.228.10.226 -j DROP  # 11 hits
iptables -A INPUT -s 78.128.113.46 -j DROP  # 11 hits
iptables -A INPUT -s 85.217.140.3 -j DROP  # 11 hits
iptables -A INPUT -s 85.217.140.4 -j DROP  # 11 hits
iptables -A INPUT -s 85.217.140.44 -j DROP  # 11 hits
iptables -A INPUT -s 109.105.209.2 -j DROP  # 10 hits
iptables -A INPUT -s 13.89.125.229 -j DROP  # 10 hits
iptables -A INPUT -s 159.223.187.181 -j DROP  # 10 hits
iptables -A INPUT -s 176.65.134.3 -j DROP  # 10 hits
iptables -A INPUT -s 176.65.148.2 -j DROP  # 10 hits
iptables -A INPUT -s 45.156.128.96 -j DROP  # 10 hits
iptables -A INPUT -s 62.67.10.15 -j DROP  # 10 hits
iptables -A INPUT -s 66.132.172.180 -j DROP  # 10 hits
iptables -A INPUT -s 93.123.109.183 -j DROP  # 10 hits

# Active Attackers (>= 3 hits)
iptables -A INPUT -s 118.193.47.212 -j DROP  # 9 hits
iptables -A INPUT -s 118.193.64.186 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.149.246 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.159.79 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.191.98 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.197.166 -j DROP  # 9 hits
iptables -A INPUT -s 159.223.177.196 -j DROP  # 9 hits
iptables -A INPUT -s 165.154.36.245 -j DROP  # 9 hits
iptables -A INPUT -s 207.90.244.18 -j DROP  # 9 hits
iptables -A INPUT -s 207.90.244.26 -j DROP  # 9 hits
iptables -A INPUT -s 207.90.244.6 -j DROP  # 9 hits
iptables -A INPUT -s 44.220.188.237 -j DROP  # 9 hits
iptables -A INPUT -s 45.142.154.114 -j DROP  # 9 hits
iptables -A INPUT -s 91.191.209.118 -j DROP  # 9 hits
iptables -A INPUT -s 91.207.115.249 -j DROP  # 9 hits
iptables -A INPUT -s 101.36.114.222 -j DROP  # 8 hits
iptables -A INPUT -s 104.218.164.192 -j DROP  # 8 hits
iptables -A INPUT -s 109.105.210.52 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.58.20 -j DROP  # 8 hits
iptables -A INPUT -s 118.194.251.141 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.139.96 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.149.47 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.153.228 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.156.136 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.156.50 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.183.209 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.197.159 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.233.95 -j DROP  # 8 hits
iptables -A INPUT -s 159.223.173.27 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.104.88 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.128.17 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.174.206 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.182.187 -j DROP  # 8 hits
iptables -A INPUT -s 178.83.200.2 -j DROP  # 8 hits
iptables -A INPUT -s 44.220.185.162 -j DROP  # 8 hits
iptables -A INPUT -s 44.220.185.180 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.103 -j DROP  # 8 hits
iptables -A INPUT -s 47.236.37.23 -j DROP  # 8 hits
iptables -A INPUT -s 47.84.103.91 -j DROP  # 8 hits
iptables -A INPUT -s 66.132.195.88 -j DROP  # 8 hits
iptables -A INPUT -s 71.6.199.23 -j DROP  # 8 hits
iptables -A INPUT -s 80.94.95.94 -j DROP  # 8 hits
iptables -A INPUT -s 176.65.148.37 -j DROP  # 7 hits
iptables -A INPUT -s 101.36.108.158 -j DROP  # 7 hits
iptables -A INPUT -s 109.105.209.5 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.189.134 -j DROP  # 7 hits
iptables -A INPUT -s 152.32.228.20 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.19.159 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.19.231 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.5.27 -j DROP  # 7 hits
iptables -A INPUT -s 185.180.141.2 -j DROP  # 7 hits
iptables -A INPUT -s 185.180.141.32 -j DROP  # 7 hits
iptables -A INPUT -s 195.178.110.204 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.234 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.237 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.185.5 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.194 -j DROP  # 7 hits
iptables -A INPUT -s 45.142.154.116 -j DROP  # 7 hits
iptables -A INPUT -s 45.142.154.41 -j DROP  # 7 hits
iptables -A INPUT -s 45.156.128.51 -j DROP  # 7 hits
iptables -A INPUT -s 45.156.128.97 -j DROP  # 7 hits
iptables -A INPUT -s 47.251.25.232 -j DROP  # 7 hits
iptables -A INPUT -s 66.132.172.215 -j DROP  # 7 hits
iptables -A INPUT -s 86.54.31.40 -j DROP  # 7 hits
iptables -A INPUT -s 89.248.167.131 -j DROP  # 7 hits
iptables -A INPUT -s 91.230.168.168 -j DROP  # 7 hits
iptables -A INPUT -s 98.80.4.89 -j DROP  # 7 hits
iptables -A INPUT -s 101.36.111.179 -j DROP  # 6 hits
iptables -A INPUT -s 106.75.11.5 -j DROP  # 6 hits
iptables -A INPUT -s 106.75.13.117 -j DROP  # 6 hits
iptables -A INPUT -s 106.75.9.232 -j DROP  # 6 hits
iptables -A INPUT -s 135.222.40.73 -j DROP  # 6 hits
iptables -A INPUT -s 15.237.177.126 -j DROP  # 6 hits
iptables -A INPUT -s 178.20.210.190 -j DROP  # 6 hits
iptables -A INPUT -s 185.242.226.104 -j DROP  # 6 hits
iptables -A INPUT -s 185.242.226.126 -j DROP  # 6 hits
iptables -A INPUT -s 207.90.244.4 -j DROP  # 6 hits
iptables -A INPUT -s 45.142.154.38 -j DROP  # 6 hits
iptables -A INPUT -s 45.91.64.7 -j DROP  # 6 hits
iptables -A INPUT -s 47.245.142.160 -j DROP  # 6 hits
iptables -A INPUT -s 47.245.143.73 -j DROP  # 6 hits
iptables -A INPUT -s 47.250.152.22 -j DROP  # 6 hits
iptables -A INPUT -s 47.250.80.121 -j DROP  # 6 hits
iptables -A INPUT -s 47.251.141.241 -j DROP  # 6 hits
iptables -A INPUT -s 47.254.156.86 -j DROP  # 6 hits
iptables -A INPUT -s 47.88.59.135 -j DROP  # 6 hits
iptables -A INPUT -s 64.62.156.152 -j DROP  # 6 hits
iptables -A INPUT -s 65.49.1.182 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.172.138 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.172.185 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.186.176 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.195.93 -j DROP  # 6 hits
iptables -A INPUT -s 71.6.134.235 -j DROP  # 6 hits
iptables -A INPUT -s 8.209.201.115 -j DROP  # 6 hits
iptables -A INPUT -s 8.209.207.15 -j DROP  # 6 hits
iptables -A INPUT -s 8.216.8.122 -j DROP  # 6 hits
iptables -A INPUT -s 80.94.95.87 -j DROP  # 6 hits
iptables -A INPUT -s 98.80.4.98 -j DROP  # 6 hits
iptables -A INPUT -s 45.142.154.30 -j DROP  # 5 hits
iptables -A INPUT -s 106.75.13.225 -j DROP  # 5 hits
iptables -A INPUT -s 118.193.36.220 -j DROP  # 5 hits
iptables -A INPUT -s 143.110.180.162 -j DROP  # 5 hits
iptables -A INPUT -s 147.185.132.82 -j DROP  # 5 hits
iptables -A INPUT -s 152.32.216.70 -j DROP  # 5 hits
iptables -A INPUT -s 176.65.134.34 -j DROP  # 5 hits
iptables -A INPUT -s 178.62.55.235 -j DROP  # 5 hits
iptables -A INPUT -s 18.97.5.126 -j DROP  # 5 hits
iptables -A INPUT -s 194.164.107.6 -j DROP  # 5 hits
iptables -A INPUT -s 195.184.76.169 -j DROP  # 5 hits
iptables -A INPUT -s 20.171.9.56 -j DROP  # 5 hits
iptables -A INPUT -s 203.55.131.4 -j DROP  # 5 hits
iptables -A INPUT -s 203.55.131.5 -j DROP  # 5 hits
iptables -A INPUT -s 216.218.206.66 -j DROP  # 5 hits
iptables -A INPUT -s 218.94.108.146 -j DROP  # 5 hits
iptables -A INPUT -s 24.199.87.217 -j DROP  # 5 hits
iptables -A INPUT -s 36.35.166.11 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.185.229 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.188.78 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.101 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.105 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.107 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.110 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.12 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.31 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.93 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.128.164 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.128.56 -j DROP  # 5 hits
iptables -A INPUT -s 64.62.156.132 -j DROP  # 5 hits
iptables -A INPUT -s 64.62.156.212 -j DROP  # 5 hits
iptables -A INPUT -s 64.62.156.222 -j DROP  # 5 hits
iptables -A INPUT -s 64.62.156.24 -j DROP  # 5 hits
iptables -A INPUT -s 64.62.156.94 -j DROP  # 5 hits
iptables -A INPUT -s 65.49.1.132 -j DROP  # 5 hits
iptables -A INPUT -s 65.49.1.222 -j DROP  # 5 hits
iptables -A INPUT -s 65.49.1.232 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.172.101 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.172.102 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.172.109 -j DROP  # 5 hits
iptables -A INPUT -s 67.187.208.66 -j DROP  # 5 hits
iptables -A INPUT -s 80.82.70.133 -j DROP  # 5 hits
iptables -A INPUT -s 87.251.64.141 -j DROP  # 5 hits
iptables -A INPUT -s 91.196.152.22 -j DROP  # 5 hits
iptables -A INPUT -s 91.230.168.23 -j DROP  # 5 hits
iptables -A INPUT -s 194.163.159.81 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.156.182 -j DROP  # 4 hits
iptables -A INPUT -s 91.196.152.107 -j DROP  # 4 hits
iptables -A INPUT -s 103.74.21.65 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.209.4 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.213 -j DROP  # 4 hits
iptables -A INPUT -s 148.153.56.174 -j DROP  # 4 hits
iptables -A INPUT -s 152.53.191.99 -j DROP  # 4 hits
iptables -A INPUT -s 164.90.168.217 -j DROP  # 4 hits
iptables -A INPUT -s 165.154.173.104 -j DROP  # 4 hits
iptables -A INPUT -s 165.227.111.119 -j DROP  # 4 hits
iptables -A INPUT -s 176.223.15.113 -j DROP  # 4 hits
iptables -A INPUT -s 176.32.193.16 -j DROP  # 4 hits
iptables -A INPUT -s 194.164.107.4 -j DROP  # 4 hits
iptables -A INPUT -s 195.184.76.128 -j DROP  # 4 hits
iptables -A INPUT -s 195.184.76.231 -j DROP  # 4 hits
iptables -A INPUT -s 195.250.79.2 -j DROP  # 4 hits
iptables -A INPUT -s 198.11.180.76 -j DROP  # 4 hits
iptables -A INPUT -s 20.169.83.214 -j DROP  # 4 hits
iptables -A INPUT -s 20.55.73.223 -j DROP  # 4 hits
iptables -A INPUT -s 206.81.17.114 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.211.148 -j DROP  # 4 hits
iptables -A INPUT -s 35.203.211.183 -j DROP  # 4 hits
iptables -A INPUT -s 37.10.113.210 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.128.167 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.129.60 -j DROP  # 4 hits
iptables -A INPUT -s 47.251.242.234 -j DROP  # 4 hits
iptables -A INPUT -s 47.254.14.239 -j DROP  # 4 hits
iptables -A INPUT -s 47.254.158.193 -j DROP  # 4 hits
iptables -A INPUT -s 47.254.200.103 -j DROP  # 4 hits
iptables -A INPUT -s 47.74.26.96 -j DROP  # 4 hits
iptables -A INPUT -s 47.77.218.117 -j DROP  # 4 hits
iptables -A INPUT -s 47.77.223.125 -j DROP  # 4 hits
iptables -A INPUT -s 47.77.235.14 -j DROP  # 4 hits
iptables -A INPUT -s 47.84.114.18 -j DROP  # 4 hits
iptables -A INPUT -s 47.84.115.39 -j DROP  # 4 hits
iptables -A INPUT -s 47.84.133.27 -j DROP  # 4 hits
iptables -A INPUT -s 47.84.136.17 -j DROP  # 4 hits
iptables -A INPUT -s 47.84.136.87 -j DROP  # 4 hits
iptables -A INPUT -s 64.227.168.58 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.156.122 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.156.80 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.197.122 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.197.152 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.197.32 -j DROP  # 4 hits
iptables -A INPUT -s 65.49.1.152 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.111 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.189 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.193 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.211 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.35 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.36 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.39 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.43 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.186.168 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.87 -j DROP  # 4 hits
iptables -A INPUT -s 71.6.232.27 -j DROP  # 4 hits
iptables -A INPUT -s 8.211.152.223 -j DROP  # 4 hits
iptables -A INPUT -s 8.216.15.41 -j DROP  # 4 hits
iptables -A INPUT -s 8.216.2.69 -j DROP  # 4 hits
iptables -A INPUT -s 80.94.95.102 -j DROP  # 4 hits
iptables -A INPUT -s 86.54.31.36 -j DROP  # 4 hits
iptables -A INPUT -s 87.121.84.40 -j DROP  # 4 hits
iptables -A INPUT -s 91.196.152.83 -j DROP  # 4 hits
iptables -A INPUT -s 91.230.168.215 -j DROP  # 4 hits
iptables -A INPUT -s 91.231.89.129 -j DROP  # 4 hits
iptables -A INPUT -s 91.231.89.144 -j DROP  # 4 hits
iptables -A INPUT -s 91.231.89.250 -j DROP  # 4 hits
iptables -A INPUT -s 94.102.49.155 -j DROP  # 4 hits
iptables -A INPUT -s 216.218.206.67 -j DROP  # 3 hits
iptables -A INPUT -s 104.232.79.58 -j DROP  # 3 hits
iptables -A INPUT -s 118.194.250.245 -j DROP  # 3 hits
iptables -A INPUT -s 128.203.202.236 -j DROP  # 3 hits
iptables -A INPUT -s 135.237.126.195 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.109 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.122 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.150 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.129 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.139 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.148 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.133.40 -j DROP  # 3 hits
iptables -A INPUT -s 150.107.36.236 -j DROP  # 3 hits
iptables -A INPUT -s 157.230.189.200 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.149.91 -j DROP  # 3 hits
iptables -A INPUT -s 164.163.24.11 -j DROP  # 3 hits
iptables -A INPUT -s 165.154.120.13 -j DROP  # 3 hits
iptables -A INPUT -s 168.144.82.54 -j DROP  # 3 hits
iptables -A INPUT -s 176.65.148.132 -j DROP  # 3 hits
iptables -A INPUT -s 192.210.198.202 -j DROP  # 3 hits
iptables -A INPUT -s 194.164.107.5 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.174 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.209 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.213 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.220 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.34 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.65 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.69 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.94 -j DROP  # 3 hits
iptables -A INPUT -s 20.223.168.112 -j DROP  # 3 hits
iptables -A INPUT -s 20.65.184.116 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.17 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.19 -j DROP  # 3 hits
iptables -A INPUT -s 35.203.211.145 -j DROP  # 3 hits
iptables -A INPUT -s 36.255.223.187 -j DROP  # 3 hits
iptables -A INPUT -s 40.76.124.166 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.165 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.53 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.128.98 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.129.62 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.129.63 -j DROP  # 3 hits
iptables -A INPUT -s 45.33.112.95 -j DROP  # 3 hits
iptables -A INPUT -s 47.236.196.80 -j DROP  # 3 hits
iptables -A INPUT -s 47.236.90.15 -j DROP  # 3 hits
iptables -A INPUT -s 47.237.2.150 -j DROP  # 3 hits
iptables -A INPUT -s 47.237.87.73 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.128.112 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.13.179 -j DROP  # 3 hits