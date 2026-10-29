# Brute-Force Log Analyzer

A Python script that reads an SSH-style authentication log and flags IP
addresses that look like brute-force attempts.

## What it does
- Reads a log file line by line
- Finds failed login attempts
- Counts failures per IP address
- detects "many failures, then a success" from the same IP, brute force

## Usage
Use to detect multiple login attempts on a system and FLAG that ip and create a alert

## Sample output
FLAGGED: 192.0.2.20 -> 5 failures
ALERT: 192.0.2.44 had 4 failures before success
ALERT: 198.51.100.23 had 1 failures before success

## How to Run

### Requirements
- Python 3
- A sample SSH authentication log file

### Run the Analyzer

1. Clone or download this repository.
2. Open a terminal in the project directory.
3. Run:

```bash
python analyzer.py
```

The analyzer reads `sample_auth.log` and generates a report of failed login attempts.

## Detection Logic

The tool:
- Extracts source IP addresses from SSH-style authentication log entries.
- Counts failed password attempts for each IP.
- Flags IP addresses that reach the configured failure threshold.
- Detects a failure-then-success pattern.
- Sorts the report by the number of failed attempts.

## Testing and Results

Test the analyzer using synthetic authentication logs containing:
- An IP with repeated failed logins followed by a successful login.
- An IP with repeated failures but no subsequent success.
- A normal successful login.

**Test results:** Add your actual results after running the tests. Do not claim detection accuracy or false-positive rates without measuring them.

## Limitations

- The current threshold counts failures across the entire log file rather than within a defined time window.
- The tool analyzes SSH-style log entries and is not a complete intrusion detection system.
- Detection results depend on the format and quality of the input logs.

## Future Improvements

- Add command-line arguments for selecting a log file.
- Add automated tests with pytest.
- Evaluate detection performance using larger synthetic log datasets.
- Improve detection logic and reporting.


## Limitations
- Works on one log format only
- The log is fake sample data, not from a real system
