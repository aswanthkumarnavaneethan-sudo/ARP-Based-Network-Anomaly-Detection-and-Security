@echo off
title NETGUARD — Public Cloudflare Secure Tunnel
color 0A
cls

echo ==============================================================================
echo          NETGUARD — Network Security & ARP Threat Detection System
echo                       Public Cloudflare Tunnel
echo ==============================================================================
echo.
echo [*] Exposing local hardware sniffer (Wi-Fi 172.100.x.x) to a public HTTPS link...
echo [*] The URL below is accessible from any phone, laptop, or projector globally.
echo.

cd /d "%~dp0"
cloudflared.exe tunnel --url http://127.0.0.1:5000

pause
