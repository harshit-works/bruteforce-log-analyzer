failed_counts = {}

with open ("auth.log") as f:
    for line in f:
        if "Failed password" in line:
            words = line.split()
            if "from" in words:
                index = words.index("from")+1
                if index < len(words):
                    ip = words[index]
                    if ip in failed_counts:
                        failed_counts[ip] = failed_counts[ip] + 1
                    else:
                        failed_counts[ip] = 1
print(failed_counts)           
                
