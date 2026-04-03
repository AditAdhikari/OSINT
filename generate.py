import json
import random
from datetime import datetime, timedelta

# 🔥 Realistic names
first_names = ["ram", "sita", "hari", "gita", "aayush", "sabin", "nabin", "ramesh", "suman", "priya"]
last_names = ["sharma", "adhikari", "karki", "thapa", "kc", "rai", "limbu", "gurung", "magar", "basnet"]

domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]

companies = ["Adobe", "LinkedIn", "Facebook", "Twitter", "Dropbox", "Yahoo", "Canva", "GitHub"]
types = ["credential", "personal", "email", "password"]

data = []

# 🎯 Create 1000 unique users
users = []
for i in range(1000):
    fname = random.choice(first_names)
    lname = random.choice(last_names)
    num = random.randint(1, 999)

    email = f"{fname}.{lname}{num}@{random.choice(domains)}"
    users.append(email)

# 🔥 Each user appears 5–8 times
for email in users:
    repeat = random.randint(5, 8)

    for _ in range(repeat):
        record = {
            "email": email,
            "name": random.choice(companies),
            "type": random.choice(types),
            "date": str(datetime.now() - timedelta(days=random.randint(0, 4000)))[:10],
            "passwordIncluded": random.choice([True, False]),
            "severity": random.randint(1, 10)
        }

        data.append(record)

# Save JSON
with open("data/breaches.json", "w") as f:
    json.dump(data, f, indent=2)

print(f"✅ Generated {len(data)} records successfully!")