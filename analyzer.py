import argparse
from datetime import datetime, timedelta
THRESHOLD = 5

def extract_ip(line):
    words = line.split()
    if "from" in words:
        index = words.index("from")+1
        if index < len(words):
            return words[index]
            
    return None 

def extract_timestamp(line):
     parts = line.split()
     if len(parts) < 3:
          return None
     timestamp_text = " ".join(parts[:3])
     try:
          return datetime.strptime(timestamp_text, "%b %d %H:%M:%S")
     except ValueError:
          return None   

def analyze_log(file_path):
     failed_counts = {}
     alerts = []
     failed_times = {}
     try:
          with open (file_path) as f:
               for line in f:
                    ip = extract_ip(line)
                    if ip is None:
                         continue 
                    if "Failed password" in line:
                         failed_counts[ip] = failed_counts.get(ip, 0)+1

                         timestamp = extract_timestamp(line)
                         if timestamp is None:
                              continue
                         if ip not in failed_times:
                              failed_times[ip] = []
                         failed_times[ip].append(timestamp)

                         cutoff = timestamp - timedelta(minutes=5)
                         failed_times[ip] = [
                              t for t in failed_times[ip] if t >= cutoff
                         ]
                         if len(failed_times[ip]) >= THRESHOLD:
                              print(f"BRUTE FORCE DETECTED: {ip}")

                    elif "Accepted password" in line:
                         count = failed_counts.get(ip, 0)
                         timestamp = extract_timestamp(line)
                         if timestamp is None:
                              continue 
                         cutoff = timestamp - timedelta(minutes=5)
                         recent_failures = [
                              t for t in failed_times.get(ip,[])
                              if t >= cutoff
                         ]
                         if len(recent_failures) >= THRESHOLD:
                              alerts.append((ip, len(recent_failures)))
     except FileNotFoundError:
          print(f"Error: File not found {file_path}")
          return None
     return failed_counts, alerts

def print_report(failed_counts, alerts):
     sorted_ips = sorted(
          failed_counts.items(),
          key=lambda item: item[1],
          reverse=True
     )
     for ip, count in sorted_ips:
          if count >= THRESHOLD:
               print(f"FLAGGED: {ip} -> {count} failures")
          else:
            print(f"NORMAL: {ip} -> {count} failures")

     for ip, count in alerts:
          print(f"ALERT: {ip} had {count} failures before success")

def main():
     parser = argparse.ArgumentParser(
          description="Analyze SSH authentication logs for suspicious login activity"
     )
     parser.add_argument("logfile", help="Path for the log file")
     args = parser.parse_args()
     result = analyze_log(args.logfile)

     if result is not None:
          counts, alerts = result
          print_report(counts, alerts)

if __name__ == "__main__":
     main()
 
