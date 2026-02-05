import streamlit as st
import pandas as pd
import time
import os

st.set_page_config(page_title="Insider Threat Dashboard", page_icon="🚨")
st.title("🚨 Real-Time Insider Threat Detection")

placeholder = st.empty()

while True:
    if os.path.exists("alerts.csv"):
        df = pd.read_csv("alerts.csv")

        st.error(f"🚨 Insider Threats Detected: {len(df)}")
        placeholder.dataframe(df.tail(10))
    else:
        st.success("✅ No threats detected yet")

    time.sleep(3)
