@echo off
title CyberShield Controlled Threat Simulation
echo ===================================================
echo Starting CyberShield Controlled Threat Simulation...
echo ===================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0trigger_controlled_threats.ps1"
pause
