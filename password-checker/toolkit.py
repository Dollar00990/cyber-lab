import random
import string


def generate_password(length):
    if length < 8:
        return None

    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(string.punctuation)
    ]

    all_chars = (
        string.ascii_letters +
        string.digits +
        string.punctuation
    )

    for _ in range(length - 4):
        password.append(random.choice(all_chars))

    random.shuffle(password)

    return "".join(password)


def check_password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1

    if any(c.islower() for c in password):
        score += 1

    if any(c.isupper() for c in password):
        score += 1

    if any(c.isdigit() for c in password):
        score += 1

    if any(not c.isalnum() for c in password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    else:
        return "Strong"


while True:
    print("\n" + "=" * 35)
    print(" PASSWORD SECURITY TOOLKIT ")
    print("=" * 35)
    print("1. Generate Password")
    print("2. Check Password Strength")
    print("3. Exit")
    print("=" * 35)

    choice = input("Choose an option: ")

    if choice == "1":
        try:
            length = int(input("Password length: "))

            password = generate_password(length)

            if password:
                print("\nGenerated Password:")
                print(password)
                print(f"Strength: {check_password_strength(password)}")
            else:
                print("Password must be at least 8 characters.")

        except ValueError:
            print("Enter a valid number.")

    elif choice == "2":
        password = input("Enter Password: ")
        strength = check_password_strength(password)

        print(f"\nPassword Strength: {strength}")

    elif choice == "3":
        print("Goodbye!")
        break

    else:
        print("Invalid choice. Try again.")