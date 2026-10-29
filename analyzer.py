THRESHOLD = 5

def extract_ip(line):
    words = line.split()
    if "from" in words:
        index = words.index("from")+1
        if index < len(words):
            return words[index]
            
    return None 

def analyze_log(file_path):
     failed_counts = {}
     alerts = []
     try:
          with open (file_path) as f:
               for line in f:
                    ip = extract_ip(line)
                    if ip is None:
                         continue 
                    if "Failed password" in line:
                         failed_counts[ip] = failed_counts.get(ip, 0)+1
                    elif "Accepted password" in line:
                         count = failed_counts.get(ip, 0)

                         if count >= THRESHOLD:
                              alerts.append((ip,count))
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
            print(f"ALERT: {ip} had {count} failures before success")

     for ip, count in alerts:
          print(f"ALERT: {ip} had {count} failures before success")

def main():
     result = analyze_log("sample_auth.log")

     if result is not None:
          counts, alerts = result
          print_report(counts, alerts)

if __name__ == "__main__":
     main()   
                
