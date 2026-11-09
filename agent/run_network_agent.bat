@echo off
title CyberShield Network Activity Agent
echo ===================================================
echo Starting CyberShield Live Network Activity Collector...
echo ===================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0cybershield_agent.ps1"
pause
