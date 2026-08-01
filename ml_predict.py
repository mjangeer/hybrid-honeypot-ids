#!/usr/bin/env python3

import json

import joblib

import numpy as np
import sys

batch_path = sys.argv[1] if len(sys.argv) > 1 else "."

print("Loading model and vectorizer...")

model = joblib.load("honeypot_ml_model.pkl")

vectorizer = joblib.load("honeypot_tfidf.pkl")



print("Loading session features...")

with open(f"{batch_path}/session_features.json") as f:
    data = json.load(f)



results = []



sensitive_words = ["shadow","passwd","id_rsa","authorized_keys"]

recon_words = ["whoami","uname","id","netstat","ps","last"]

priv_words = ["sudo","su","chmod 777","chown"]



for session_id, info in data.items():



    commands = info.get("commands", [])

    failed_logins = info.get("failed_logins", 0)



    commands_text = " ".join(commands)

    command_count = len(commands)



    # ------- engineered features (same as Colab) -------------



    unique_commands = len(set(commands_text.split()))

    diversity_score = unique_commands / max(command_count,1)



    sensitive_access_count = sum(w in commands_text for w in sensitive_words)
    burst_score = 1 if command_count > 40 else 0
    recon_count = sum(w in commands_text for w in recon_words)
    privilege_attempts = sum(w in commands_text for w in priv_words)

    sudo_flag = int("sudo" in commands_text or "su" in commands_text)
    download_flag = int("wget" in commands_text or "curl" in commands_text)
    sensetive_access = int("/etc/passwd" in commands_text or "/etc/shadow" in  commands_text or "id_rsa" in commands_text)
    recon_flag = int(any(w in commands_text for w in recon_words))
    persistence_flag = int("cron" in commands_text or "backdoor" in commands_text or "chmod 777" in commands_text)

    commands_per_login = command_count / (failed_logins + 1)

    numeric_features = np.array([
       failed_logins,
       command_count,
       diversity_score,
       sensitive_access_count,
       burst_score,
       recon_count,
       privilege_attempts,
       sudo_flag,
       download_flag,
       sensetive_access,
       recon_flag,
       persistence_flag,
       commands_per_login
])

    #----- TF-IDF------
    tfdif_vec = vectorizer.transform([commands_text]).toarray()[0]

    #------ combine ------
    full_vector = np.concatenate([tfdif_vec, numeric_features]).reshape(1,-1)

    #align featureswith trained ML model------
    expected = model.n_features_in_
    if full_vector.shape[1] < expected:
     padding = np.zeros((1, expected - full_vector.shape[1]))
     full_vector = np.concatenate([full_vector, padding], axis=1)
    elif full_vector.shape[1] > expected:
     full_vector = full_vector[:, :expected]


    prediction = model.predict(full_vector)[0]
    confidence = model.predict_proba(full_vector)[0]

    results.append({
    "session_id": session_id,
    "ml_prediction": "Suspicious" if prediction == 1 else "Normal",
    "confidence": float(max(confidence)),
    "command_count": command_count
    })

with open(f"{batch_path}/ml_predictions.json","w") as f:
    json.dump(results, f, indent=2)

print ("ML Prediction saved") 
