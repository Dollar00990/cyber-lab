import random
import string


def generate_password(length):
    if length < 8:
        print("Password length must be at least 8.")
        return

    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(string.punctuation)
    ]

    all_characters = (
        string.ascii_letters +
        string.digits +
        string.punctuation
    )

    for _ in range(length - 4):
        password.append(random.choice(all_characters))

    random.shuffle(password)

    return "".join(password)


length = int(input("Enter password length: "))

password = generate_password(length)

if password:
    print(f"\nGenerated Password:\n{password}")