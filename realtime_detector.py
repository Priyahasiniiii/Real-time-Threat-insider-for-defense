import pandas as pd
import pickle
import time
import os
from plyer import notification   # 🔔 Notification module

# ================= LOAD MODEL =================
model = pickle.load(open("insider_model.pkl", "rb"))

log_file = "live_logs.csv"
alert_file = "alerts.csv"

processed_rows = 0
user_baseline = {}

# ================= NOTIFICATION FUNCTION =================
def send_notification(title, message):
    notification.notify(
        title=title,
        message=message,
        timeout=5
    )

# ================= CREATE ALERT FILE IF NOT EXISTS =================
if not os.path.exists(alert_file):
    with open(alert_file, "w", encoding="utf-8") as f:
        f.write("UserID,RiskScore,Reason\n")

print("🔄 Real-time Insider Threat Monitoring Started...")

# ================= MAIN LOOP =================
while True:
    if os.path.exists(log_file):
        data = pd.read_csv(log_file)

        # Safety check
        required_cols = ["UserID", "LoginHour", "FilesAccessed", "DataDownloadedMB", "FailedLogins"]
        if not all(col in data.columns for col in required_cols):
            print("⏳ Waiting for correct log format...")
            time.sleep(2)
            continue

        if len(data) > processed_rows:
            new_data = data.iloc[processed_rows:]
            processed_rows = len(data)

            for _, row in new_data.iterrows():
                uid = row["UserID"]

                # ================= USER BASELINE =================
                if uid not in user_baseline:
                    user_baseline[uid] = {
                        "files": row["FilesAccessed"],
                        "data": row["DataDownloadedMB"]
                    }

                avg_files = user_baseline[uid]["files"]
                avg_data = user_baseline[uid]["data"]

                # ================= DEVIATION =================
                file_dev = row["FilesAccessed"] / max(avg_files, 1)
                data_dev = row["DataDownloadedMB"] / max(avg_data, 1)

                # ================= ML PREDICTION =================
                X = [[
                    row["LoginHour"],
                    row["FilesAccessed"],
                    row["DataDownloadedMB"],
                    row["FailedLogins"]
                ]]
                ml_pred = model.predict(X)[0]

                # ================= RISK CALCULATION =================
                risk = 0
                reasons = []

                if ml_pred == -1:
                    risk += 40
                    reasons.append("ML anomaly detected")

                if row["LoginHour"] < 5:
                    risk += 20
                    reasons.append("Unusual login hour")

                if file_dev > 5:
                    risk += 20
                    reasons.append("Excessive file access")

                if data_dev > 5:
                    risk += 20
                    reasons.append("Mass data download")

                if row["FailedLogins"] > 3:
                    risk += 10
                    reasons.append("Multiple failed logins")

                # ================= ALERT + NOTIFICATION =================
                if risk >= 60:
                    with open(alert_file, "a", encoding="utf-8") as f:
                        f.write(f"{uid},{risk},{' | '.join(reasons)}\n")

                    print(f"🚨 Insider Threat Detected → User: {uid} | Risk: {risk}")

                    # 🔔 DESKTOP NOTIFICATION
                    send_notification(
                        title="🚨 Insider Threat Detected",
                        message=f"User: {uid}\nRisk Score: {risk}\nReason: {', '.join(reasons)}"
                    )
                else:
                    print(f"✅ Normal Activity → User: {uid}")

                # ================= UPDATE BASELINE =================
                user_baseline[uid]["files"] = (avg_files + row["FilesAccessed"]) / 2
                user_baseline[uid]["data"] = (avg_data + row["DataDownloadedMB"]) / 2

    time.sleep(2)   # real-time check every 2 seconds
