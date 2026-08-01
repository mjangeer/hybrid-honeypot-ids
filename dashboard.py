from flask import Flask, render_template
import json
import os

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

def load_json(name):
    try:
        with open(name) as f:
            return json.load(f)
    except:
        return []

@app.route("/")
@app.route("/<batch_name>")
def index(batch_name=None):
    batch_dir = "attack_batches"
    batches = []
    
    if os.path.exists(batch_dir):
        batches = sorted([d for d in os.listdir(batch_dir) if os.path.isdir(os.path.join(batch_dir, d))])
    
    if batches and batch_name is None:
        batch_name = batches[0]
    
    if batch_name and batches:
        base_path = f"{batch_dir}/{batch_name}/"
        s1 = load_json(f"{base_path}session_features.json")
        s2 = load_json(f"{base_path}stage2_alerts.json")
        s3 = load_json(f"{base_path}ml_predictions.json")
    else:
        s1 = load_json("session_features.json")
        s2 = load_json("stage2_alerts.json")
        s3 = load_json("ml_predictions.json")
        batch_name = "current"

    combined = []

    # Handle dict or list formats
    if isinstance(s1, dict):
        s1_items = [(k, v) for k, v in s1.items()]
    elif isinstance(s1, list):
        s1_items = [(x.get("session_id", "unknown"), x) for x in s1]
    else:
        s1_items = []

    for sid, info in s1_items:
        print(f"DEBUG: Looking for session_id: {sid}")
        print(f"DEBUG: Stage 2 has: {[x.get('session_id') for x in s2]}")
        print(f"DEBUG: Stage 3 has: {[x.get('session_id') for x in s3]}")
        stage2_match = next((x for x in s2 if str(x.get("session_id")) == str(sid)), {})
        stage3_match = next((x for x in s3 if str(x.get("session_id")) == str(sid)), {})

        reasons = stage2_match.get("reasons", [])
        reasons_text = ", ".join(reasons[:3]) if reasons else "None detected"


        combined.append({
        "session": sid or "unknown",
        "commands": len(info.get("commands", [])),
        "failed": info.get("failed_logins", 0),
        "risk": stage2_match.get("risk_score", 0),
        "ml": stage3_match.get("ml_prediction", "Unknown"),
        "confidence": round(stage3_match.get("confidence", 0) * 100, 1) if stage3_match.get("confidence") else 0,
        "reasons": reasons_text,
        "verdict": determine_verdict(
         stage2_match.get("risk_score", 0),
         stage3_match.get("ml_prediction", "Unknown")
            )
        })

    stats = {
        "total": len(combined),
        "high_risk": sum(1 for r in combined if r["verdict"] == "High Risk"),
        "suspicious": sum(1 for r in combined if r["verdict"] == "Suspicious"),
        "low": sum(1 for r in combined if r["verdict"] == "Low"),
        "normal": sum(1 for r in combined if r["verdict"] == "Normal")
    }

    return render_template("dashboard.html", 
                     rows=combined, 
                     stats=stats,
                     batches=batches,
                     current_batch=batch_name)



def determine_verdict(risk_score, ml_pred):
    if risk_score >= 8 and ml_pred == "Suspicious":
        return "High Risk"
    elif risk_score >= 5 and ml_pred == "Suspicious":
        return "Suspicious"
    elif risk_score >= 1:
        return "Low"
    else:
        return "Normal"



if __name__ == "__main__":
    print("/n Starting Dashboard on http://192.168.254.134:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
