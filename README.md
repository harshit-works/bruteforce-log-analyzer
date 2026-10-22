# Brute-Force Log Analyzer

A Python script that reads an SSH-style authentication log and flags IP
addresses that look like brute-force attempts.

## What it does
- Reads a log file line by line
- Finds failed login attempts
- Counts failures per IP address
- <flags IPs above a threshold, if you've built it>
- <detects "many failures, then a success" from the same IP, if built>

## Usage
python analyzer.py sample_auth.log

## Sample output
(paste real output from your script here)

## Status
In progress. Next steps:
- [ ] Add a configurable failure threshold
- [ ] Detect failures followed by a success
- [ ] Read the file path from the command line
- [ ] Write tests with pytest
- [ ] Measure detection results on a larger test log

## Limitations
- Works on one log format only
- The log is fake sample data, not from a real system
