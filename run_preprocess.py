import pandas as pd

df = pd.read_csv('merged_dataset.csv')

df.isna().sum()

# TCP packets with missing ports
tcp_missing = df[(df["protocol"] == 6) &
                 (df["src_port"].isna() | df["dst_port"].isna())]

print("TCP packets missing ports:", len(tcp_missing))

# UDP packets missing UDP length
udp_missing = df[(df["protocol"] == 17) &
                 (df["udp_length"].isna())]

print("UDP packets missing udp_length:", len(udp_missing))

# ICMP packets missing type/code
icmp_missing = df[(df["protocol"] == 1) &
                  (df["icmp_type"].isna() | df["icmp_code"].isna())]

print("ICMP packets missing fields:", len(icmp_missing))


# 1. DROP UNUSED L2 / META COLUMNS

df = df.drop(columns=["pcap_file", "timestamp"])

df = df.drop(columns=["src_mac", "dst_mac", "eth_type"])


# 2. DROP NON-IP ROWS (STRUCTURAL IP MISSING)
ip_cols = [
    "src_ip", "dst_ip", "ip_version", "ttl",
    "ip_length", "tos", "id",
    "flags_ip", "fragment", "protocol"
]

df = df.dropna(subset=ip_cols)


# 3. HANDLE STRUCTURAL TRANSPORT-LAYER MISSING VALUES

df["src_port"] = df["src_port"].fillna(-1)
df["dst_port"] = df["dst_port"].fillna(-1)

df["seq"] = df["seq"].fillna(-1)
df["ack"] = df["ack"].fillna(-1)
df["window"] = df["window"].fillna(-1)

df["udp_length"] = df["udp_length"].fillna(-1)

df["icmp_type"] = df["icmp_type"].fillna(-1)
df["icmp_code"] = df["icmp_code"].fillna(-1)

df.info()

numeric_cols = [
    "src_port",
    "dst_port",
    "seq",
    "ack",
    "window",
    "udp_length",
    "icmp_type",
    "icmp_code"
]

df[numeric_cols] = df[numeric_cols].fillna(-1)

df["is_tcp"] = (df["protocol"] == 6).astype(int)
df["is_udp"] = (df["protocol"] == 17).astype(int)
df["is_icmp"] = (df["protocol"] == 1).astype(int)

df.info()

df.isna().sum()

df['Attack Type'].value_counts()

df.info()

from sklearn.preprocessing import LabelEncoder

src_encoder = LabelEncoder()
dst_encoder = LabelEncoder()

df["src_ip"] = src_encoder.fit_transform(df["src_ip"])
df["dst_ip"] = dst_encoder.fit_transform(df["dst_ip"])
import joblib
import os
os.makedirs("saved", exist_ok=True)
joblib.dump(src_encoder, "saved/src_encoder.pkl")
joblib.dump(dst_encoder, "saved/dst_encoder.pkl")

import sys
print("Encoders saved successfully!")
sys.exit(0)



import matplotlib.pyplot as plt
import seaborn as sns

# 1. DISTRIBUTION OF ATTACK TYPES
plt.figure(figsize=(10,5))
df["Attack Type"].value_counts().plot(kind="bar")
plt.title("Distribution of Attack Types")
plt.xlabel("Attack Type")
plt.ylabel("Count")
plt.xticks(rotation=45)
plt.show()


# 2. MEAN COMPARISON (NUMERIC FEATURES)
attack_means = df.groupby("Attack Type").mean(numeric_only=True)

print("Mean feature values per attack type:\n")
print(attack_means)

plt.figure(figsize=(14,8))
sns.heatmap(attack_means, cmap="coolwarm")
plt.title("Mean Feature Heatmap per Attack Type")
plt.show()


# 3. BOX PLOTS (KEY FEATURES)
key_features = [
    "packet_length",
    "ttl",
    "ip_length",
    "payload_size"
]

for feature in key_features:
    plt.figure(figsize=(12,5))
    sns.boxplot(x="Attack Type", y=feature, data=df)
    plt.xticks(rotation=45)
    plt.title(f"{feature} Distribution per Attack Type")
    plt.show()


# 4. HEATMAP (CORRELATION INSIGHT)
plt.figure(figsize=(12,8))
sns.heatmap(df.corr(numeric_only=True), cmap="coolwarm")
plt.title("Feature Correlation Heatmap")
plt.show()

# 5. PROTOCOL USAGE PER ATTACK TYPE
plt.figure(figsize=(10,5))
pd.crosstab(df["Attack Type"], df["protocol"]).plot(kind="bar", stacked=True)
plt.title("Protocol Usage per Attack Type")
plt.ylabel("Count")
plt.xticks(rotation=45)
plt.show()


# 6. FLAG BEHAVIOR (IMPORTANT FOR IDS)
flag_cols = ["syn", "ack_flag", "fin", "rst", "psh", "urg"]

df.groupby("Attack Type")[flag_cols].mean().plot(
    kind="bar",
    figsize=(12,6)
)

plt.title("TCP Flag Behavior per Attack Type")
plt.ylabel("Average Flag Value")
plt.xticks(rotation=45)
plt.show()

# 7. PORT BEHAVIOR ANALYSIS
# Destination port distribution
plt.figure(figsize=(12,5))
sns.boxplot(x="Attack Type", y="dst_port", data=df)
plt.xticks(rotation=45)
plt.title("Destination Port Distribution per Attack Type")
plt.show()

# Average port usage per attack
print("\nAverage destination port per attack type:\n")
print(df.groupby("Attack Type")["dst_port"].mean())



# 8. HANDLE OUTLIERS BEFORE MODELING
# Clip extreme values using robust percentile-based bounds.
# This is a common choice for network data because real attack traffic can contain very large values.

numeric_cols = [
    col for col in df.select_dtypes(include=['number']).columns
    if col not in ['Attack Type', 'label']
]

print('Checking numeric columns for outliers...')

for col in numeric_cols:
    q1 = df[col].quantile(0.01)
    q3 = df[col].quantile(0.99)
    lower = q1
    upper = q3

    clipped_count = ((df[col] < lower) | (df[col] > upper)).sum()
    if clipped_count > 0:
        df[col] = df[col].clip(lower=lower, upper=upper)
        print(f'{col}: clipped {clipped_count} values to [{lower:.4f}, {upper:.4f}]')
    else:
        print(f'{col}: no extreme values detected')

print('\nOutlier handling complete.')
print(df[numeric_cols].describe().T[['min','max','mean','std']])


# Save the cleaned dataset for modeling
df.to_csv('cleaned_dataset.csv', index=False)

