#!/bin/bash
# LLM Honeypot Intelligence - Firewall Blocklist
# Generated: 2026-04-14 05:48 UTC
# Total: 530 IPs | Blocked: 45 scanners + 68 repeat + 260 active

# Mass Scanners (known infrastructure)
iptables -A INPUT -s 167.94.146.53 -j DROP  # scanner, 19 hits
iptables -A INPUT -s 167.94.146.56 -j DROP  # scanner, 15 hits
iptables -A INPUT -s 167.94.146.62 -j DROP  # scanner, 15 hits
iptables -A INPUT -s 167.94.146.59 -j DROP  # scanner, 14 hits
iptables -A INPUT -s 167.94.146.48 -j DROP  # scanner, 13 hits
iptables -A INPUT -s 167.94.146.61 -j DROP  # scanner, 12 hits
iptables -A INPUT -s 167.94.146.60 -j DROP  # scanner, 11 hits
iptables -A INPUT -s 167.94.146.55 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 167.94.146.63 -j DROP  # scanner, 10 hits
iptables -A INPUT -s 184.105.247.195 -j DROP  # scanner, 9 hits
iptables -A INPUT -s 167.94.146.49 -j DROP  # scanner, 9 hits
iptables -A INPUT -s 167.94.146.51 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.54 -j DROP  # scanner, 8 hits
iptables -A INPUT -s 167.94.146.52 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 167.94.146.57 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 205.210.31.212 -j DROP  # scanner, 7 hits
iptables -A INPUT -s 167.94.146.50 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 167.94.146.58 -j DROP  # scanner, 6 hits
iptables -A INPUT -s 184.105.247.252 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 198.235.24.252 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 205.210.31.209 -j DROP  # scanner, 5 hits
iptables -A INPUT -s 198.235.24.174 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.53 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 198.235.24.72 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.103 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.250 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 205.210.31.91 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 71.6.135.131 -j DROP  # scanner, 4 hits
iptables -A INPUT -s 184.105.247.196 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.126 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 198.235.24.209 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.165 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.235 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.46 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.78 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 205.210.31.83 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 66.240.205.34 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 71.6.147.254 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 74.82.47.5 -j DROP  # scanner, 3 hits
iptables -A INPUT -s 184.105.139.69 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 198.235.24.203 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 198.235.24.46 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 205.210.31.11 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 205.210.31.214 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 74.82.47.3 -j DROP  # scanner, 1 hits

# Repeat Offenders (>= 10 hits)
iptables -A INPUT -s 176.65.132.254 -j DROP  # 10379 hits
iptables -A INPUT -s 87.251.64.159 -j DROP  # 1776 hits
iptables -A INPUT -s 85.11.167.11 -j DROP  # 348 hits
iptables -A INPUT -s 80.94.92.182 -j DROP  # 202 hits
iptables -A INPUT -s 206.221.176.60 -j DROP  # 178 hits
iptables -A INPUT -s 178.221.54.184 -j DROP  # 129 hits
iptables -A INPUT -s 45.205.1.5 -j DROP  # 112 hits
iptables -A INPUT -s 81.29.142.100 -j DROP  # 112 hits
iptables -A INPUT -s 45.205.1.110 -j DROP  # 105 hits
iptables -A INPUT -s 2.57.122.238 -j DROP  # 86 hits
iptables -A INPUT -s 45.33.114.45 -j DROP  # 81 hits
iptables -A INPUT -s 3.131.220.121 -j DROP  # 77 hits
iptables -A INPUT -s 92.118.39.72 -j DROP  # 49 hits
iptables -A INPUT -s 103.199.123.32 -j DROP  # 46 hits
iptables -A INPUT -s 46.151.178.13 -j DROP  # 40 hits
iptables -A INPUT -s 134.122.28.163 -j DROP  # 39 hits
iptables -A INPUT -s 138.68.58.48 -j DROP  # 39 hits
iptables -A INPUT -s 147.182.209.206 -j DROP  # 39 hits
iptables -A INPUT -s 157.230.13.255 -j DROP  # 39 hits
iptables -A INPUT -s 157.245.168.43 -j DROP  # 39 hits
iptables -A INPUT -s 157.245.173.26 -j DROP  # 39 hits
iptables -A INPUT -s 167.172.121.65 -j DROP  # 39 hits
iptables -A INPUT -s 167.71.31.191 -j DROP  # 39 hits
iptables -A INPUT -s 170.187.158.208 -j DROP  # 39 hits
iptables -A INPUT -s 173.255.226.126 -j DROP  # 39 hits
iptables -A INPUT -s 173.255.226.239 -j DROP  # 39 hits
iptables -A INPUT -s 192.81.129.161 -j DROP  # 39 hits
iptables -A INPUT -s 204.48.29.133 -j DROP  # 39 hits
iptables -A INPUT -s 23.239.29.27 -j DROP  # 39 hits
iptables -A INPUT -s 45.33.102.121 -j DROP  # 39 hits
iptables -A INPUT -s 45.33.114.92 -j DROP  # 39 hits
iptables -A INPUT -s 16.58.56.214 -j DROP  # 38 hits
iptables -A INPUT -s 45.205.1.26 -j DROP  # 35 hits
iptables -A INPUT -s 18.116.101.220 -j DROP  # 34 hits
iptables -A INPUT -s 18.218.118.203 -j DROP  # 34 hits
iptables -A INPUT -s 3.129.187.38 -j DROP  # 34 hits
iptables -A INPUT -s 92.118.39.76 -j DROP  # 34 hits
iptables -A INPUT -s 3.143.162.210 -j DROP  # 32 hits
iptables -A INPUT -s 3.130.168.2 -j DROP  # 32 hits
iptables -A INPUT -s 3.151.241.153 -j DROP  # 31 hits
iptables -A INPUT -s 204.76.203.206 -j DROP  # 29 hits
iptables -A INPUT -s 45.153.34.204 -j DROP  # 28 hits
iptables -A INPUT -s 128.199.225.7 -j DROP  # 25 hits
iptables -A INPUT -s 103.97.215.11 -j DROP  # 22 hits
iptables -A INPUT -s 3.132.26.232 -j DROP  # 21 hits
iptables -A INPUT -s 81.29.142.6 -j DROP  # 20 hits
iptables -A INPUT -s 92.63.197.22 -j DROP  # 20 hits
iptables -A INPUT -s 152.32.233.95 -j DROP  # 19 hits
iptables -A INPUT -s 185.150.191.236 -j DROP  # 18 hits
iptables -A INPUT -s 193.124.20.242 -j DROP  # 16 hits
iptables -A INPUT -s 37.44.238.107 -j DROP  # 15 hits
iptables -A INPUT -s 45.135.194.113 -j DROP  # 15 hits
iptables -A INPUT -s 112.5.73.216 -j DROP  # 14 hits
iptables -A INPUT -s 93.123.72.166 -j DROP  # 13 hits
iptables -A INPUT -s 207.90.244.26 -j DROP  # 12 hits
iptables -A INPUT -s 45.82.78.102 -j DROP  # 12 hits
iptables -A INPUT -s 47.250.163.215 -j DROP  # 12 hits
iptables -A INPUT -s 95.214.52.233 -j DROP  # 12 hits
iptables -A INPUT -s 106.75.13.117 -j DROP  # 11 hits
iptables -A INPUT -s 204.76.203.215 -j DROP  # 11 hits
iptables -A INPUT -s 3.134.216.108 -j DROP  # 11 hits
iptables -A INPUT -s 79.124.59.78 -j DROP  # 11 hits
iptables -A INPUT -s 185.242.226.10 -j DROP  # 10 hits
iptables -A INPUT -s 45.156.128.91 -j DROP  # 10 hits
iptables -A INPUT -s 47.84.140.197 -j DROP  # 10 hits
iptables -A INPUT -s 5.187.35.142 -j DROP  # 10 hits
iptables -A INPUT -s 8.135.238.47 -j DROP  # 10 hits
iptables -A INPUT -s 93.123.109.183 -j DROP  # 10 hits

# Active Attackers (>= 3 hits)
iptables -A INPUT -s 118.194.236.137 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.149.19 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.149.246 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.150.215 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.164.139 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.178.47 -j DROP  # 9 hits
iptables -A INPUT -s 152.32.206.49 -j DROP  # 9 hits
iptables -A INPUT -s 162.243.84.219 -j DROP  # 9 hits
iptables -A INPUT -s 165.154.138.33 -j DROP  # 9 hits
iptables -A INPUT -s 207.90.244.4 -j DROP  # 9 hits
iptables -A INPUT -s 45.156.128.86 -j DROP  # 9 hits
iptables -A INPUT -s 87.251.64.141 -j DROP  # 9 hits
iptables -A INPUT -s 107.150.117.219 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.32.88 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.58.20 -j DROP  # 8 hits
iptables -A INPUT -s 124.198.131.185 -j DROP  # 8 hits
iptables -A INPUT -s 130.12.180.174 -j DROP  # 8 hits
iptables -A INPUT -s 147.185.132.180 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.197.12 -j DROP  # 8 hits
iptables -A INPUT -s 152.32.197.121 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.120.30 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.162.102 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.163.199 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.182.72 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.36.245 -j DROP  # 8 hits
iptables -A INPUT -s 165.154.59.168 -j DROP  # 8 hits
iptables -A INPUT -s 193.176.31.147 -j DROP  # 8 hits
iptables -A INPUT -s 194.88.98.89 -j DROP  # 8 hits
iptables -A INPUT -s 45.82.78.100 -j DROP  # 8 hits
iptables -A INPUT -s 47.251.49.115 -j DROP  # 8 hits
iptables -A INPUT -s 66.132.195.73 -j DROP  # 8 hits
iptables -A INPUT -s 78.128.113.46 -j DROP  # 8 hits
iptables -A INPUT -s 103.203.57.20 -j DROP  # 7 hits
iptables -A INPUT -s 109.105.210.62 -j DROP  # 7 hits
iptables -A INPUT -s 18.97.26.61 -j DROP  # 7 hits
iptables -A INPUT -s 193.124.20.254 -j DROP  # 7 hits
iptables -A INPUT -s 193.142.146.230 -j DROP  # 7 hits
iptables -A INPUT -s 193.176.31.153 -j DROP  # 7 hits
iptables -A INPUT -s 194.88.98.85 -j DROP  # 7 hits
iptables -A INPUT -s 204.76.203.56 -j DROP  # 7 hits
iptables -A INPUT -s 221.228.10.226 -j DROP  # 7 hits
iptables -A INPUT -s 37.10.113.221 -j DROP  # 7 hits
iptables -A INPUT -s 44.220.188.90 -j DROP  # 7 hits
iptables -A INPUT -s 51.159.110.167 -j DROP  # 7 hits
iptables -A INPUT -s 66.132.195.66 -j DROP  # 7 hits
iptables -A INPUT -s 80.94.95.83 -j DROP  # 7 hits
iptables -A INPUT -s 1.95.195.50 -j DROP  # 6 hits
iptables -A INPUT -s 106.75.11.5 -j DROP  # 6 hits
iptables -A INPUT -s 112.91.141.33 -j DROP  # 6 hits
iptables -A INPUT -s 152.32.180.86 -j DROP  # 6 hits
iptables -A INPUT -s 170.39.218.48 -j DROP  # 6 hits
iptables -A INPUT -s 185.226.197.32 -j DROP  # 6 hits
iptables -A INPUT -s 185.242.226.73 -j DROP  # 6 hits
iptables -A INPUT -s 193.176.31.150 -j DROP  # 6 hits
iptables -A INPUT -s 194.88.98.92 -j DROP  # 6 hits
iptables -A INPUT -s 207.90.244.17 -j DROP  # 6 hits
iptables -A INPUT -s 207.90.244.18 -j DROP  # 6 hits
iptables -A INPUT -s 207.90.244.19 -j DROP  # 6 hits
iptables -A INPUT -s 207.90.244.6 -j DROP  # 6 hits
iptables -A INPUT -s 37.10.113.213 -j DROP  # 6 hits
iptables -A INPUT -s 45.156.128.94 -j DROP  # 6 hits
iptables -A INPUT -s 65.49.20.68 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.195.55 -j DROP  # 6 hits
iptables -A INPUT -s 101.36.111.179 -j DROP  # 5 hits
iptables -A INPUT -s 106.75.14.37 -j DROP  # 5 hits
iptables -A INPUT -s 109.105.209.2 -j DROP  # 5 hits
iptables -A INPUT -s 118.193.38.178 -j DROP  # 5 hits
iptables -A INPUT -s 118.193.40.131 -j DROP  # 5 hits
iptables -A INPUT -s 141.98.10.164 -j DROP  # 5 hits
iptables -A INPUT -s 141.98.8.122 -j DROP  # 5 hits
iptables -A INPUT -s 147.185.132.195 -j DROP  # 5 hits
iptables -A INPUT -s 147.185.132.69 -j DROP  # 5 hits
iptables -A INPUT -s 152.32.211.139 -j DROP  # 5 hits
iptables -A INPUT -s 176.120.22.135 -j DROP  # 5 hits
iptables -A INPUT -s 193.124.20.252 -j DROP  # 5 hits
iptables -A INPUT -s 193.176.31.149 -j DROP  # 5 hits
iptables -A INPUT -s 193.176.31.156 -j DROP  # 5 hits
iptables -A INPUT -s 193.176.31.157 -j DROP  # 5 hits
iptables -A INPUT -s 194.88.98.86 -j DROP  # 5 hits
iptables -A INPUT -s 194.88.98.88 -j DROP  # 5 hits
iptables -A INPUT -s 194.88.98.94 -j DROP  # 5 hits
iptables -A INPUT -s 195.140.214.23 -j DROP  # 5 hits
iptables -A INPUT -s 195.140.214.24 -j DROP  # 5 hits
iptables -A INPUT -s 195.140.214.28 -j DROP  # 5 hits
iptables -A INPUT -s 20.64.106.38 -j DROP  # 5 hits
iptables -A INPUT -s 20.84.144.171 -j DROP  # 5 hits
iptables -A INPUT -s 216.218.206.68 -j DROP  # 5 hits
iptables -A INPUT -s 23.94.252.104 -j DROP  # 5 hits
iptables -A INPUT -s 37.10.113.217 -j DROP  # 5 hits
iptables -A INPUT -s 44.220.185.122 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.114 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.13 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.44 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.88 -j DROP  # 5 hits
iptables -A INPUT -s 45.142.154.90 -j DROP  # 5 hits
iptables -A INPUT -s 45.148.10.121 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.128.88 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.128.89 -j DROP  # 5 hits
iptables -A INPUT -s 45.156.128.93 -j DROP  # 5 hits
iptables -A INPUT -s 47.251.182.239 -j DROP  # 5 hits
iptables -A INPUT -s 47.84.204.199 -j DROP  # 5 hits
iptables -A INPUT -s 62.164.177.41 -j DROP  # 5 hits
iptables -A INPUT -s 65.49.20.66 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.186.164 -j DROP  # 5 hits
iptables -A INPUT -s 66.132.195.43 -j DROP  # 5 hits
iptables -A INPUT -s 91.191.209.118 -j DROP  # 5 hits
iptables -A INPUT -s 91.230.168.234 -j DROP  # 5 hits
iptables -A INPUT -s 94.102.49.193 -j DROP  # 5 hits
iptables -A INPUT -s 213.177.179.101 -j DROP  # 4 hits
iptables -A INPUT -s 95.214.53.42 -j DROP  # 4 hits
iptables -A INPUT -s 176.65.148.37 -j DROP  # 4 hits
iptables -A INPUT -s 31.57.216.224 -j DROP  # 4 hits
iptables -A INPUT -s 101.36.121.22 -j DROP  # 4 hits
iptables -A INPUT -s 109.105.209.3 -j DROP  # 4 hits
iptables -A INPUT -s 114.215.197.233 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.171 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.64 -j DROP  # 4 hits
iptables -A INPUT -s 147.185.132.99 -j DROP  # 4 hits
iptables -A INPUT -s 148.153.188.254 -j DROP  # 4 hits
iptables -A INPUT -s 176.65.132.107 -j DROP  # 4 hits
iptables -A INPUT -s 178.16.55.208 -j DROP  # 4 hits
iptables -A INPUT -s 193.124.20.243 -j DROP  # 4 hits
iptables -A INPUT -s 193.124.20.245 -j DROP  # 4 hits
iptables -A INPUT -s 193.124.20.249 -j DROP  # 4 hits
iptables -A INPUT -s 193.176.31.151 -j DROP  # 4 hits
iptables -A INPUT -s 193.176.31.152 -j DROP  # 4 hits
iptables -A INPUT -s 193.176.31.154 -j DROP  # 4 hits
iptables -A INPUT -s 193.176.31.155 -j DROP  # 4 hits
iptables -A INPUT -s 194.88.98.83 -j DROP  # 4 hits
iptables -A INPUT -s 195.140.214.18 -j DROP  # 4 hits
iptables -A INPUT -s 195.140.214.22 -j DROP  # 4 hits
iptables -A INPUT -s 195.140.214.29 -j DROP  # 4 hits
iptables -A INPUT -s 195.184.76.135 -j DROP  # 4 hits
iptables -A INPUT -s 195.184.76.138 -j DROP  # 4 hits
iptables -A INPUT -s 195.184.76.215 -j DROP  # 4 hits
iptables -A INPUT -s 20.102.91.36 -j DROP  # 4 hits
iptables -A INPUT -s 20.163.20.206 -j DROP  # 4 hits
iptables -A INPUT -s 20.55.3.202 -j DROP  # 4 hits
iptables -A INPUT -s 216.218.206.67 -j DROP  # 4 hits
iptables -A INPUT -s 37.10.113.211 -j DROP  # 4 hits
iptables -A INPUT -s 44.220.188.120 -j DROP  # 4 hits
iptables -A INPUT -s 45.153.34.231 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.128.87 -j DROP  # 4 hits
iptables -A INPUT -s 45.156.129.60 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.104 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.106 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.107 -j DROP  # 4 hits
iptables -A INPUT -s 45.82.78.108 -j DROP  # 4 hits
iptables -A INPUT -s 47.245.13.179 -j DROP  # 4 hits
iptables -A INPUT -s 47.245.138.36 -j DROP  # 4 hits
iptables -A INPUT -s 47.251.115.200 -j DROP  # 4 hits
iptables -A INPUT -s 58.212.237.19 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.194 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.201 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.209 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.186.174 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.186.194 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.195.33 -j DROP  # 4 hits
iptables -A INPUT -s 71.6.165.200 -j DROP  # 4 hits
iptables -A INPUT -s 8.211.32.231 -j DROP  # 4 hits
iptables -A INPUT -s 8.216.5.206 -j DROP  # 4 hits
iptables -A INPUT -s 86.54.31.36 -j DROP  # 4 hits
iptables -A INPUT -s 9.234.8.54 -j DROP  # 4 hits
iptables -A INPUT -s 91.231.89.15 -j DROP  # 4 hits
iptables -A INPUT -s 87.121.84.8 -j DROP  # 3 hits
iptables -A INPUT -s 101.36.109.144 -j DROP  # 3 hits
iptables -A INPUT -s 118.193.56.235 -j DROP  # 3 hits
iptables -A INPUT -s 118.26.104.179 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.165 -j DROP  # 3 hits
iptables -A INPUT -s 147.185.132.249 -j DROP  # 3 hits
iptables -A INPUT -s 162.216.150.163 -j DROP  # 3 hits
iptables -A INPUT -s 165.154.163.10 -j DROP  # 3 hits
iptables -A INPUT -s 178.128.252.70 -j DROP  # 3 hits
iptables -A INPUT -s 178.83.200.2 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.197.33 -j DROP  # 3 hits
iptables -A INPUT -s 185.242.226.91 -j DROP  # 3 hits
iptables -A INPUT -s 185.93.89.192 -j DROP  # 3 hits
iptables -A INPUT -s 193.124.20.248 -j DROP  # 3 hits
iptables -A INPUT -s 193.176.31.158 -j DROP  # 3 hits
iptables -A INPUT -s 194.88.98.91 -j DROP  # 3 hits
iptables -A INPUT -s 195.140.214.19 -j DROP  # 3 hits
iptables -A INPUT -s 195.140.214.25 -j DROP  # 3 hits
iptables -A INPUT -s 195.140.214.26 -j DROP  # 3 hits
iptables -A INPUT -s 195.140.214.30 -j DROP  # 3 hits
iptables -A INPUT -s 195.178.110.204 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.142 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.171 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.33 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.84 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.89 -j DROP  # 3 hits
iptables -A INPUT -s 195.184.76.94 -j DROP  # 3 hits
iptables -A INPUT -s 199.45.155.89 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.12 -j DROP  # 3 hits
iptables -A INPUT -s 37.10.113.210 -j DROP  # 3 hits
iptables -A INPUT -s 37.10.113.219 -j DROP  # 3 hits
iptables -A INPUT -s 37.10.113.220 -j DROP  # 3 hits
iptables -A INPUT -s 40.76.124.195 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.129.62 -j DROP  # 3 hits
iptables -A INPUT -s 45.156.129.63 -j DROP  # 3 hits
iptables -A INPUT -s 47.236.244.147 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.138.141 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.138.22 -j DROP  # 3 hits
iptables -A INPUT -s 47.245.141.134 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.138.108 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.160.122 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.160.72 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.43.101 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.101.89 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.182.92 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.27.105 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.68.60 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.155.45 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.238.189 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.214.12 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.222.43 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.223.200 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.228.10 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.100.118 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.103.231 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.133.201 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.137.32 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.143.65 -j DROP  # 3 hits
iptables -A INPUT -s 47.84.200.119 -j DROP  # 3 hits
iptables -A INPUT -s 60.191.125.35 -j DROP  # 3 hits
iptables -A INPUT -s 65.49.20.67 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.203 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.221 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.45 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.97 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.162 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.163 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.168 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.175 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.187 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.186.205 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.195.44 -j DROP  # 3 hits
iptables -A INPUT -s 71.6.199.23 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.70.233 -j DROP  # 3 hits
iptables -A INPUT -s 8.209.78.193 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.169.222 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.21.19 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.47.177 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.15.47 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.17.164 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.17.84 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.3.102 -j DROP  # 3 hits
iptables -A INPUT -s 86.54.31.44 -j DROP  # 3 hits
iptables -A INPUT -s 91.196.152.105 -j DROP  # 3 hits
iptables -A INPUT -s 91.196.152.122 -j DROP  # 3 hits
iptables -A INPUT -s 91.196.152.21 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.10 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.151 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.25 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.251 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.35 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.58 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.68 -j DROP  # 3 hits
iptables -A INPUT -s 91.231.89.236 -j DROP  # 3 hits
iptables -A INPUT -s 91.231.89.248 -j DROP  # 3 hits
iptables -A INPUT -s 91.231.89.47 -j DROP  # 3 hits