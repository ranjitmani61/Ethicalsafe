import re
import logging

logger = logging.getLogger(__name__)

def check_password_strength(password):
    try:
        score = 0
        feedback = []
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters")
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        if re.search(r"[0-9]", password):
            score += 1
        else:
            feedback.append("Add numbers")
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        else:
            feedback.append("Add special characters")
        strength = "Weak" if score < 3 else "Medium" if score < 4 else "Strong"
        return {"status": "Success", "strength": strength, "score": score, "feedback": feedback}
    except Exception as e:
        logger.error(f"Password check error: {str(e)}")
        return {"error": f"Password check failed: {str(e)}"}