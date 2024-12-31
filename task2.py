# password analyzer

import re

def evaluate_password_strength(password):
    # Initialize a strength score
    score = 0
    feedback = []

    # Check minimum length
    if len(password) < 8:
        feedback.append("Password is too short. Use at least 8 characters.")
    else:
        score += 1

    # Check for uppercase and lowercase
    if not any(char.islower() for char in password):
        feedback.append("Include at least one lowercase letter.")
    else:
        score += 1

    if not any(char.isupper() for char in password):
        feedback.append("Include at least one uppercase letter.")
    else:
        score += 1

    # Check for numbers
    if not any(char.isdigit() for char in password):
        feedback.append("Include at least one number.")
    else:
        score += 1

    # Check for special characters
    if not any(char in "!@#$%^&*()-_=+[]{};:,.<>?/" for char in password):
        feedback.append("Include at least one special character.")
    else:
        score += 1

    # Check for common patterns or dictionary words
    common_patterns = ["123", "password", "qwerty", "abc"]
    if any(pattern in password.lower() for pattern in common_patterns):
        feedback.append("Avoid common patterns like '123', 'password', or 'qwerty'.")
    else:
        score += 1

    # Final Score Evaluation
    if score == 6:
        return "Strong password! Good job!", feedback
    elif 4 <= score < 6:
        return "Moderate password. Consider improving.", feedback
    else:
        return "Weak password. Highly recommend changes.", feedback

# Main Program
if __name__ == "__main__":
    password = input("Enter a password to analyze: ")
    strength, recommendations = evaluate_password_strength(password)
    print(f"\nPassword Strength: {strength}")
    print("\nRecommendations:")
    for rec in recommendations:
        print(f"- {rec}")
