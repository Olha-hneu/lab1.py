import re
from datetime import datetime

COMMON_WORDS = {
    "password", "qwerty", "admin", "welcome", "login", "user",
    "iloveyou", "123456", "12345678", "111111", "000000"
}

def normalize(s: str) -> str:
    """Lowercase + remove spaces and separators for comparisons."""
    return re.sub(r"[\s_\-\.]+", "", s.strip().lower())

def extract_birth_tokens(dob: str):
    """
    dob format: DD.MM.YYYY
    returns tokens like year, dd, mm, ddmm, mmdd, yyyymmdd, ddmmyyyy etc.
    """
    dt = datetime.strptime(dob, "%d.%m.%Y")
    dd = f"{dt.day:02d}"
    mm = f"{dt.month:02d}"
    yyyy = f"{dt.year:04d}"
    yy = yyyy[2:]

    tokens = {
        dd, mm, yyyy, yy,
        dd + mm, mm + dd,
        yyyy + mm + dd, dd + mm + yyyy,
        yy + mm + dd, dd + mm + yy
    }
    return tokens

def char_classes(password: str):
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_lower, has_upper, has_digit, has_special

def has_sequences(password: str) -> bool:
    """
    Detect simple sequences like 1234, abcd, qwerty (roughly).
    """
    p = password.lower()
    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
    for seq in sequences:
        for i in range(len(seq) - 3):
            if seq[i:i+4] in p:
                return True
    return False

def analyze_password(password: str, first_name: str, last_name: str, dob: str):
    issues = []
    recs = []
    score = 10  # start from max, subtract by risks

    p_norm = normalize(password)
    fn_norm = normalize(first_name)
    ln_norm = normalize(last_name)

    # 1) Personal data checks
    if fn_norm and fn_norm in p_norm:
        issues.append("Пароль містить ім’я користувача.")
        score -= 3
        recs.append("Приберіть ім’я з пароля або замініть на випадкові слова/символи.")

    if ln_norm and ln_norm in p_norm:
        issues.append("Пароль містить прізвище користувача.")
        score -= 3
        recs.append("Не використовуйте прізвище в паролі — це легко вгадується.")

    try:
        dob_tokens = extract_birth_tokens(dob)
        found_tokens = [t for t in dob_tokens if t in password]
        if found_tokens:
            issues.append(f"Пароль містить фрагменти дати народження: {', '.join(sorted(found_tokens))}.")
            score -= 3
            recs.append("Не використовуйте дату народження/рік/день/місяць у паролі.")
    except ValueError:
        issues.append("Дата народження введена у неправильному форматі (очікується DD.MM.YYYY).")
        score -= 1
        recs.append("Вводьте дату народження у форматі DD.MM.YYYY для коректної перевірки.")

    # 2) Complexity checks
    length = len(password)
    if length < 8:
        issues.append("Довжина пароля менше 8 символів.")
        score -= 4
        recs.append("Зробіть пароль довжиною щонайменше 12–16 символів.")
    elif 8 <= length < 12:
        issues.append("Довжина пароля середня (8–11 символів).")
        score -= 2
        recs.append("Рекомендується 12–16+ символів для кращого захисту.")
    elif 12 <= length < 16:
        # ok, minor note
        recs.append("Довжина хороша. Для максимального захисту можна 16+ символів.")

    has_lower, has_upper, has_digit, has_special = char_classes(password)
    classes = sum([has_lower, has_upper, has_digit, has_special])

    if classes <= 1:
        issues.append("Пароль використовує лише один тип символів (наприклад, лише літери або лише цифри).")
        score -= 4
        recs.append("Додайте комбінацію: великі/малі літери, цифри та спецсимволи.")
    elif classes == 2:
        issues.append("Пароль має лише 2 типи символів — бажано більше різноманітності.")
        score -= 2
        recs.append("Додайте третій/четвертий тип символів, наприклад спецсимволи.")
    elif classes == 3 and not has_special:
        issues.append("Немає спецсимволів — це знижує стійкість до підбору.")
        score -= 1
        recs.append("Додайте 1–2 спецсимволи (!@#$%...) у непередбачуваних місцях.")

    # repeated patterns
    if re.search(r"(.)\1\1", password):
        issues.append("Є повтори одного символу 3+ рази поспіль (наприклад, 'aaa' або '111').")
        score -= 1
        recs.append("Уникайте довгих повторів однакових символів.")

    if has_sequences(password):
        issues.append("Є прості послідовності (наприклад, 1234 або abcd/qwerty).")
        score -= 2
        recs.append("Уникайте послідовностей — вони перевіряються першими при атаках.")

    # common words
    p_low = password.lower()
    if any(w in p_low for w in COMMON_WORDS):
        issues.append("Пароль містить поширене/типове слово або шаблон (password, qwerty, 123456...).")
        score -= 3
        recs.append("Уникайте найпопулярніших слів/шаблонів. Використовуйте випадкові фрази.")

    # clamp score to 1..10
    score = max(1, min(10, score))

    # If no issues - still give good practice recommendations
    if not issues:
        recs.append("Пароль не містить очевидних ризиків. Рекомендується використовувати менеджер паролів і 2FA.")

    return {
        "score": score,
        "issues": issues,
        "recommendations": list(dict.fromkeys(recs)),  # remove duplicates, keep order
        "length": length,
        "classes": {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digits": has_digit,
            "special": has_special
        }
    }

def main():
    print("=== Password Security Analyzer ===")
    first_name = input("Ім'я (латиницею/як у паролі): ").strip()
    last_name = input("Прізвище (латиницею/як у паролі): ").strip()
    dob = input("Дата народження (DD.MM.YYYY): ").strip()
    password = input("Пароль для перевірки (тестовий): ").strip()

    result = analyze_password(password, first_name, last_name, dob)

    print("\n--- РЕЗУЛЬТАТ ---")
    print(f"Оцінка: {result['score']}/10")
    print(f"Довжина: {result['length']} символів")
    cls = result["classes"]
    print("Класи символів:", ", ".join([k for k, v in cls.items() if v]) or "немає")

    print("\nВиявлені ризики:")
    if result["issues"]:
        for i, issue in enumerate(result["issues"], 1):
            print(f"{i}. {issue}")
    else:
        print("— явних ризиків не виявлено.")

    print("\nРекомендації:")
    for i, rec in enumerate(result["recommendations"], 1):
        print(f"{i}. {rec}")

if __name__ == "__main__":
    main()
