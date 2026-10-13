
def check_password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1

    if any(char.islower() for char in password):
        score += 1

    if any(char.isupper() for char in password):
        score += 1

    if any(char.isdigit() for char in password):
        score += 1

    special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/"

    if any(char in special_chars for char in password):
        score += 1

    if score <= 2:
        return "Weak"

    elif score <= 4:
        return "Medium"

    else:
        return "Strong"

def check_password(password):
    issues = []

    if len(password) < 8:
        issues.append("At least 8 characters")

    if not any(c.islower() for c in password):
        issues.append("A lowercase letter")

    if not any(c.isupper() for c in password):
        issues.append("An uppercase letter")

    if not any(c.isdigit() for c in password):
        issues.append("A number")

    if not any(c in "!@#$%^&*" for c in password):
        issues.append("A special character")

    if len(issues) == 0:
        print("✅ Strong Password")
    else:
        print("❌ Password needs:")
        for issue in issues:
            print("-", issue)


password = input("Enter Password: ")
check_password(password)

length = len(password)

if length < 8:
    print("Very Easy to Crack")
elif length < 12:
    print("Moderate")
else:
    print("Harder to Crack")