import json

def get_live_stats(file_path):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        email_index = {}
        for item in data:
            email = item["email"].lower()
            if email not in email_index: email_index[email] = []
            email_index[email].append(item)

        stats = {
            "total_records": len(data),
            "unique_emails": len(email_index),
            "high_severity": sum(1 for b in data if b.get("severity", 0) >= 8),
            "password_leaks": sum(1 for b in data if b.get("passwordIncluded") is True)
        }
        return email_index, stats
    except:
        return {}, {"total_records": 0, "unique_emails": 0, "high_severity": 0, "password_leaks": 0}