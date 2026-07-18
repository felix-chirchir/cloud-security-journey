# lesson1_basics.py
# Felix Chirchir
# Python basics practice

# Lines starting with # are comments
# Python ignores them
# Use comments to explain what your code does

# =============================
# VARIABLES AND DATA TYPES
# ============================= 

name = "Felix Chirchir"
age = 20
city = "Nairobi"
goal = "Cloud Security Architect"
monthly_target = 5000.0
is_student = True

# ============================= 
# PRINT STATEMENTS
# ============================= 

print("=" * 40)
print("MY PROFILE")
print("=" * 40)

print(f"Name:           {name}")
print(f"Age:            {age}")
print(f"city:           {city}")
print(f"Goal:           {goal}")
print(f"Income target:  ${monthly_target}")
print(f"Student:        {is_student}")

# =============================
# SIMPLE CALCULATIONS
# =============================

print("\n" + "n" * 40)
print("CALCULATIONS")
print("=" * 40)

years_to_goal = 3
income_per_year = monthly_target * 12

print(f"Monthly target:         ${monthly_target}")
print(f"Annual target:          ${income_per_year}")
print(f"Years to goal:          {years_to_goal}")
print(f"Total by year {age + years_to_goal}:    ${income_per_year * years_to_goal}")

# =============================
# STRING METHODS
# =============================

print("\n" + "=" * 40)
print("STRING METHODS")
print("=" * 40)

print(f"Original:               {name}")
print(f"Uppercase:              {name.upper()}")
print(f"Lowercase:              {name.lower()}")
print(f"Length:                 {len(name)} characters")
print(f"Starts with Felix* {name.startswith('Felix')}")

# =============================
# USER INPUT
# =============================

print("\n" + "=" * 40)
print("INTERACTIVE SECTION")
print("=" * 40)

user_name = input("Enter your name: ")
user_age = int(input("Enter your age: "))

print(f"\nHello {user_name}!")
print(f"You are {user_age} years old.")
print(f"By 2031 you will be {user_age + 5} years old.")
print(f"If you start today you will be earning ${monthly_target}/month by then.")