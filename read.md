# Security Log Analyzer

## Project Overview

This project detects brute-force login attempts from system logs.

The system:

- Reads login logs
- Identifies failed login attempts
- Detects suspicious IP addresses
- Assigns risk levels
- Generates SOC reports
- Visualizes attack activity using bar graphs

## Technologies Used

- Python
- CSV
- Matplotlib

## Features

- Brute Force Detection
- Risk Classification
- CSV Report Generation
- Security Visualization

## Output

### Attack Analysis

![Bar Graph](attack_bargraph.png)

### SOC Report

Generated automatically as:
soc_report.csv

## Future Enhancements

- Real-time Log Monitoring
- Email Alerts
- SIEM Integration
- Machine Learning Based Detection