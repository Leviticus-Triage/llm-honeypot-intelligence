#!/bin/bash
# LLM Honeypot Intelligence - Firewall Blocklist
# Generated: 2026-03-25 13:58 UTC
# Total: 499 IPs | Blocked: 12 scanners + 64 repeat + 67 active

# Mass Scanners (known infrastructure)
iptables -A INPUT -s 167.94.146.60 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 184.105.247.254 -j DROP  # scanner, 2 hits
iptables -A INPUT -s 167.94.146.57 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 167.94.146.58 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 167.94.146.62 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 167.94.146.63 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 184.105.139.67 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 184.105.247.194 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 66.240.205.34 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 71.6.135.131 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 74.82.47.2 -j DROP  # scanner, 1 hits
iptables -A INPUT -s 80.82.77.139 -j DROP  # scanner, 1 hits

# Repeat Offenders (>= 10 hits)
iptables -A INPUT -s 107.180.88.176 -j DROP  # 238 hits
iptables -A INPUT -s 203.145.34.82 -j DROP  # 238 hits
iptables -A INPUT -s 31.14.32.6 -j DROP  # 217 hits
iptables -A INPUT -s 134.209.166.254 -j DROP  # 162 hits
iptables -A INPUT -s 134.199.196.64 -j DROP  # 161 hits
iptables -A INPUT -s 91.92.243.116 -j DROP  # 147 hits
iptables -A INPUT -s 85.217.140.8 -j DROP  # 136 hits
iptables -A INPUT -s 103.179.56.44 -j DROP  # 119 hits
iptables -A INPUT -s 68.183.66.16 -j DROP  # 112 hits
iptables -A INPUT -s 85.217.140.37 -j DROP  # 112 hits
iptables -A INPUT -s 216.155.93.75 -j DROP  # 103 hits
iptables -A INPUT -s 85.217.140.50 -j DROP  # 99 hits
iptables -A INPUT -s 85.217.140.40 -j DROP  # 93 hits
iptables -A INPUT -s 85.217.140.9 -j DROP  # 70 hits
iptables -A INPUT -s 129.212.184.91 -j DROP  # 67 hits
iptables -A INPUT -s 85.217.140.46 -j DROP  # 63 hits
iptables -A INPUT -s 85.217.140.1 -j DROP  # 54 hits
iptables -A INPUT -s 85.217.140.31 -j DROP  # 54 hits
iptables -A INPUT -s 31.14.32.4 -j DROP  # 51 hits
iptables -A INPUT -s 85.217.140.44 -j DROP  # 44 hits
iptables -A INPUT -s 85.217.140.41 -j DROP  # 44 hits
iptables -A INPUT -s 85.217.140.6 -j DROP  # 43 hits
iptables -A INPUT -s 85.217.140.5 -j DROP  # 42 hits
iptables -A INPUT -s 85.217.140.11 -j DROP  # 40 hits
iptables -A INPUT -s 165.227.95.184 -j DROP  # 39 hits
iptables -A INPUT -s 192.81.129.49 -j DROP  # 39 hits
iptables -A INPUT -s 206.189.174.255 -j DROP  # 39 hits
iptables -A INPUT -s 59.103.104.117 -j DROP  # 38 hits
iptables -A INPUT -s 85.217.140.7 -j DROP  # 34 hits
iptables -A INPUT -s 85.217.140.20 -j DROP  # 33 hits
iptables -A INPUT -s 45.205.1.110 -j DROP  # 32 hits
iptables -A INPUT -s 85.217.140.26 -j DROP  # 32 hits
iptables -A INPUT -s 85.217.140.14 -j DROP  # 30 hits
iptables -A INPUT -s 85.217.140.22 -j DROP  # 28 hits
iptables -A INPUT -s 85.217.140.15 -j DROP  # 27 hits
iptables -A INPUT -s 45.205.1.5 -j DROP  # 26 hits
iptables -A INPUT -s 16.58.56.214 -j DROP  # 24 hits
iptables -A INPUT -s 85.217.140.19 -j DROP  # 24 hits
iptables -A INPUT -s 85.217.140.45 -j DROP  # 23 hits
iptables -A INPUT -s 165.154.11.210 -j DROP  # 22 hits
iptables -A INPUT -s 79.124.40.174 -j DROP  # 22 hits
iptables -A INPUT -s 85.217.140.23 -j DROP  # 22 hits
iptables -A INPUT -s 85.217.140.34 -j DROP  # 22 hits
iptables -A INPUT -s 85.217.140.10 -j DROP  # 20 hits
iptables -A INPUT -s 144.2.91.96 -j DROP  # 19 hits
iptables -A INPUT -s 85.217.140.17 -j DROP  # 19 hits
iptables -A INPUT -s 85.217.140.27 -j DROP  # 19 hits
iptables -A INPUT -s 85.217.140.28 -j DROP  # 19 hits
iptables -A INPUT -s 85.217.140.3 -j DROP  # 19 hits
iptables -A INPUT -s 85.217.140.12 -j DROP  # 17 hits
iptables -A INPUT -s 3.130.168.2 -j DROP  # 15 hits
iptables -A INPUT -s 85.217.140.38 -j DROP  # 15 hits
iptables -A INPUT -s 118.193.45.103 -j DROP  # 14 hits
iptables -A INPUT -s 81.29.142.100 -j DROP  # 14 hits
iptables -A INPUT -s 85.217.140.33 -j DROP  # 13 hits
iptables -A INPUT -s 45.205.1.8 -j DROP  # 12 hits
iptables -A INPUT -s 92.63.197.22 -j DROP  # 12 hits
iptables -A INPUT -s 46.151.178.13 -j DROP  # 11 hits
iptables -A INPUT -s 31.14.32.8 -j DROP  # 11 hits
iptables -A INPUT -s 85.217.140.25 -j DROP  # 11 hits
iptables -A INPUT -s 45.142.154.103 -j DROP  # 10 hits
iptables -A INPUT -s 45.142.154.37 -j DROP  # 10 hits
iptables -A INPUT -s 85.217.140.42 -j DROP  # 10 hits
iptables -A INPUT -s 85.217.140.53 -j DROP  # 10 hits

# Active Attackers (>= 3 hits)
iptables -A INPUT -s 85.217.140.16 -j DROP  # 9 hits
iptables -A INPUT -s 85.217.140.18 -j DROP  # 9 hits
iptables -A INPUT -s 115.231.78.11 -j DROP  # 8 hits
iptables -A INPUT -s 170.39.218.251 -j DROP  # 8 hits
iptables -A INPUT -s 170.39.218.32 -j DROP  # 8 hits
iptables -A INPUT -s 85.217.140.24 -j DROP  # 8 hits
iptables -A INPUT -s 85.217.140.35 -j DROP  # 8 hits
iptables -A INPUT -s 85.217.140.52 -j DROP  # 8 hits
iptables -A INPUT -s 118.193.40.131 -j DROP  # 7 hits
iptables -A INPUT -s 164.92.87.77 -j DROP  # 7 hits
iptables -A INPUT -s 207.154.228.48 -j DROP  # 7 hits
iptables -A INPUT -s 89.190.156.94 -j DROP  # 7 hits
iptables -A INPUT -s 18.218.118.203 -j DROP  # 6 hits
iptables -A INPUT -s 3.129.187.38 -j DROP  # 6 hits
iptables -A INPUT -s 3.131.220.121 -j DROP  # 6 hits
iptables -A INPUT -s 4.145.113.4 -j DROP  # 6 hits
iptables -A INPUT -s 66.132.172.101 -j DROP  # 6 hits
iptables -A INPUT -s 85.217.140.36 -j DROP  # 6 hits
iptables -A INPUT -s 204.76.203.206 -j DROP  # 5 hits
iptables -A INPUT -s 118.193.33.249 -j DROP  # 5 hits
iptables -A INPUT -s 18.97.19.134 -j DROP  # 5 hits
iptables -A INPUT -s 185.180.141.10 -j DROP  # 5 hits
iptables -A INPUT -s 185.226.197.32 -j DROP  # 5 hits
iptables -A INPUT -s 85.217.140.32 -j DROP  # 5 hits
iptables -A INPUT -s 174.138.52.189 -j DROP  # 4 hits
iptables -A INPUT -s 101.126.24.74 -j DROP  # 4 hits
iptables -A INPUT -s 139.159.206.165 -j DROP  # 4 hits
iptables -A INPUT -s 185.180.141.7 -j DROP  # 4 hits
iptables -A INPUT -s 64.62.197.167 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.130 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.35 -j DROP  # 4 hits
iptables -A INPUT -s 66.132.172.39 -j DROP  # 4 hits
iptables -A INPUT -s 78.68.236.146 -j DROP  # 4 hits
iptables -A INPUT -s 85.217.140.2 -j DROP  # 4 hits
iptables -A INPUT -s 92.118.39.30 -j DROP  # 4 hits
iptables -A INPUT -s 95.214.52.233 -j DROP  # 4 hits
iptables -A INPUT -s 138.68.233.55 -j DROP  # 3 hits
iptables -A INPUT -s 14.103.118.153 -j DROP  # 3 hits
iptables -A INPUT -s 167.172.114.4 -j DROP  # 3 hits
iptables -A INPUT -s 182.148.185.127 -j DROP  # 3 hits
iptables -A INPUT -s 185.226.197.33 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.17 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.18 -j DROP  # 3 hits
iptables -A INPUT -s 207.90.244.19 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.41.139 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.50.149 -j DROP  # 3 hits
iptables -A INPUT -s 47.250.54.138 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.252.250 -j DROP  # 3 hits
iptables -A INPUT -s 47.251.80.203 -j DROP  # 3 hits
iptables -A INPUT -s 47.254.95.160 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.223.226 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.228.106 -j DROP  # 3 hits
iptables -A INPUT -s 47.77.229.26 -j DROP  # 3 hits
iptables -A INPUT -s 51.159.110.167 -j DROP  # 3 hits
iptables -A INPUT -s 64.225.112.209 -j DROP  # 3 hits
iptables -A INPUT -s 64.62.156.10 -j DROP  # 3 hits
iptables -A INPUT -s 64.62.156.38 -j DROP  # 3 hits
iptables -A INPUT -s 65.49.1.142 -j DROP  # 3 hits
iptables -A INPUT -s 65.49.20.69 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.141 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.180 -j DROP  # 3 hits
iptables -A INPUT -s 66.132.172.182 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.128.112 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.136.6 -j DROP  # 3 hits
iptables -A INPUT -s 8.211.45.194 -j DROP  # 3 hits
iptables -A INPUT -s 8.216.16.104 -j DROP  # 3 hits
iptables -A INPUT -s 91.230.168.31 -j DROP  # 3 hits