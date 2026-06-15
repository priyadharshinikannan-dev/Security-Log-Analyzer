from collections import Counter
import csv
import matplotlib.pyplot as plt

# Store failed login IPs
failed_ips = []

# Read log file
with open("logs.txt", "r") as file:
    for line in file:

        if "Failed login" in line:
            ip = line.split()[-1]
            failed_ips.append(ip)

# Count failed attempts
ip_count = Counter(failed_ips)

# Risk Calculation Function
def calculate_risk(count):

    if count >= 5:
        return "High"

    elif count >= 3:
        return "Medium"

    else:
        return "Low"

print("=" * 50)
print("      SECURITY LOG ANALYSIS REPORT")
print("=" * 50)

# Display Analysis
for ip, count in ip_count.items():

    risk = calculate_risk(count)

    print(f"\nIP Address      : {ip}")
    print(f"Failed Attempts : {count}")
    print(f"Risk Level      : {risk}")

    if count >= 3:
        print("Alert           : Possible Brute Force Attack")

# Export CSV Report
with open("soc_report.csv", "w", newline="") as report:

    writer = csv.writer(report)

    writer.writerow([
        "IP Address",
        "Failed Attempts",
        "Risk Level"
    ])

    for ip, count in ip_count.items():

        risk = calculate_risk(count)

        writer.writerow([
            ip,
            count,
            risk
        ])

# Summary
total_failed = len(failed_ips)

high_risk_count = sum(
    1 for ip, count in ip_count.items()
    if count >= 5
)

medium_risk_count = sum(
    1 for ip, count in ip_count.items()
    if 3 <= count < 5
)

print("\n" + "=" * 50)
print("SOC SUMMARY")
print("=" * 50)

print(f"Total Failed Login Attempts : {total_failed}")
print(f"Unique Suspicious IPs       : {len(ip_count)}")
print(f"High Risk IPs              : {high_risk_count}")
print(f"Medium Risk IPs            : {medium_risk_count}")

# GRAPH GENERATION
ips = list(ip_count.keys())
attempts = list(ip_count.values())

plt.figure(figsize=(8,5))

bars = plt.bar(
    ips,
    attempts
)

plt.title("Failed Login Attempts by IP Address")
plt.xlabel("IP Address")
plt.ylabel("Failed Login Attempts")

# Display values on top of bars
for bar in bars:

    height = bar.get_height()

    plt.text(
        bar.get_x() + bar.get_width()/2,
        height,
        str(int(height)),
        ha='center',
        va='bottom'
    )

plt.xticks(rotation=20)

plt.tight_layout()

plt.savefig("attack_bargraph.png")

print("\nBar Graph Saved Successfully!")
print("File generated: attack_bargraph.png")

plt.show()
