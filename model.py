import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle

data = pd.read_csv("logs.csv")

X = data[["LoginHour", "FilesAccessed", "DataDownloadedMB", "FailedLogins"]]

model = IsolationForest(contamination=0.25, random_state=42)
model.fit(X)

pickle.dump(model, open("insider_model.pkl", "wb"))

print("✅ Insider Threat Model Trained")
