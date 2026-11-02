# Python SSH Authentication Log Analyzer

A Python-based security log analysis tool that monitors SSH authentication logs, identifies suspicious login activity, and detects potential brute-force attacks using a rolling five-minute detection window.

## Features

- Extracts source IP addresses from SSH authentication logs.
- Counts failed login attempts per IP address.
- Detects brute-force attempts (5 or more failures within 5 minutes).
- Identifies successful logins following repeated failed attempts.
- Prevents duplicate brute-force alerts during the same detection cycle.
- Handles missing files and invalid timestamps.
- Generates a structured security report.
- Supports command-line execution using `argparse`.

## Technologies Used

- Python 3
- File Handling
- Dictionaries and Sets
- Datetime and Timedelta
- Argparse
- Pytest

## Project Structure

```text
log-analyzer/
├── analyzer.py
├── sample_auth.log
├── test_analyzer.py
└── README.md
```

## How It Works

1. Reads SSH authentication log entries.
2. Extracts IP addresses and timestamps.
3. Tracks failed login attempts for each IP.
4. Maintains a rolling five-minute window.
5. Generates alerts when suspicious authentication patterns are detected.
6. Displays total failed logins and security alerts.

## Detection Rules

| Detection | Condition |
|---|---|
| Brute-force attempt | 5 or more failed logins within 5 minutes |
| Success after failures | Successful login after 5 or more failures within 5 minutes |

## Installation and Usage

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Navigate to the project directory:

```bash
cd log-analyzer
```

Run the analyzer:

```bash
python analyzer.py sample_auth.log
```

View command-line help:

```bash
python analyzer.py --help
```

## Run Tests

Install pytest:

```bash
pip install pytest
```

Run the automated tests:

```bash
pytest -v
```

## Testing

The test suite covers:

- IP address extraction.
- Invalid or missing IP addresses.
- Brute-force detection within five minutes.
- Failed attempts outside the detection window.
- Successful login after repeated failures.
- Failed attempts without a successful login.
- Multiple attack cycles from the same IP.

## Limitations

- Designed for sample SSH authentication logs and learning purposes.
- Assumes log entries are chronologically ordered.
- Uses timestamps without year information.
- Not intended as a production SIEM or real-time monitoring solution.

## Future Improvements

- Support additional authentication log formats.
- Add structured JSON reporting.
- Integrate with a SIEM platform.
- Improve detection and incident investigation capabilities.

## Disclaimer

This project is developed for educational and defensive cybersecurity purposes.
