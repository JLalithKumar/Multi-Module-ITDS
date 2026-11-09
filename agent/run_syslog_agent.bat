@echo off
title CyberShield System Logs Collector Agent
echo ===================================================
echo Starting CyberShield Live System Logs Collector...
echo ===================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0cybershield_syslog_agent.ps1"
pause
