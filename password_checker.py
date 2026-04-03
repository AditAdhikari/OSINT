import re

def check_password_strength(password):
    score = 0
    feedback = []
    if len(password) >= 12: score += 2
    elif len(password) >= 8: score += 1
    else: feedback.append("⚠️ Too short (8+ chars)")
    
    if re.search(r"\d", password): score += 1
    else: feedback.append("⚠️ Add a number")
    
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password): score += 1
    else: feedback.append("⚠️ Mix Case letters")
    
    if re.search(r"[!@#$%^&*]", password): score += 1
    else: feedback.append("⚠️ Add a special char")

    labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong", 5: "Excellent"}
    return {"score": score, "label": labels.get(score, "Weak"), "feedback": feedback}