import json
import sys


RISK_RULES = {

    "failed_login_threshold": 1,

    "high_risk_commands": ["wget", "curl", "chmod", "bash", "sh"],

    "command_count_threshold": 5

}


# -----------------------------

# Additional Behavioural Rules

 #-----------------------------



RECON_COMMANDS = [

    "whoami", "id", "uname", "pwd", "ls",

    "cat /etc/passwd", "netstat", "ps"

]



PRIV_ESC_COMMANDS = [

    "sudo", "su", "chmod", "chown", "/etc/shadow"

]





def calculate_command_rate(command_count, session_seconds):

    if session_seconds == 0:

        return 0

    return (command_count / session_seconds) * 60





def count_matching_commands(command_list, keyword_list):

    count = 0

    for cmd in command_list:

        for keyword in keyword_list:

            if keyword in cmd:

                count += 1

                break

    return count




def evaluate_session(session):

    score = 0

    reasons = []



    # ---- Rule 1: Failed logins ----

    if session.get("failed_logins", 0) > RISK_RULES["failed_login_threshold"]:

        score += 1

        reasons.append("Multiple failed login attempts")



    # ---- Rule 2: High command count ----

    if session.get("command_count", 0) > RISK_RULES["command_count_threshold"]:

        score += 1

        reasons.append("High number of executed commands")



    # ---- Rule 3: High-risk commands ----

    for cmd in session.get("commands", []):

        for risk_cmd in RISK_RULES["high_risk_commands"]:

            if risk_cmd in cmd.lower():

                score += 2

                reasons.append(f"High-risk command detected: {cmd}")

                break



    # -----------------------------

    # Additional Behaviour Rules

    # -----------------------------



    command_list = session.get("commands", [])

    command_count = len(command_list)

    session_seconds = session.get("duration", 0)



    command_rate = calculate_command_rate(command_count, session_seconds)



    if command_rate > 15:

        score += 2

        reasons.append("High command rate (possible automation)")



    recon_count = count_matching_commands(command_list, RECON_COMMANDS)



    if recon_count >= 3:

        score += 2

        reasons.append("Reconnaissance command pattern detected")



    privilege_attempts = count_matching_commands(command_list, PRIV_ESC_COMMANDS)



    if privilege_attempts >= 1:

        score += 3

        reasons.append("Privilege escalation attempt detected")



    # ---- Store metrics ----

    session["command_rate"] = command_rate

    session["recon_count"] = recon_count

    session["privilege_attempts"] = privilege_attempts



    return score, reasons
def main():

    batch_path = sys.argv[1] if len(sys.argv) > 1 else "."
    # Load Stage 1 features
    with open(f"{batch_path}/session_features.json", "r") as f:
        sessions = json.load(f)

    print("Stage 2: Rule-Based Detection Results#n")




    results = []



    for session_id, session in sessions.items():

        score, reasons = evaluate_session(session)





        if score == 0:
           risk_level = "Normal"
        elif score <= 10:
           risk_level = "Low"
        elif score <= 30:
            risk_level = "Suspicious"
        else:
            risk_level = "High"





        results.append({

        "session_id": session_id,

        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons

        })



    # Save alerts for next stages

    with open(f"{batch_path}/stage2_alerts.json", "w") as f:

        json.dump(results, f, indent=4)



    print("#n[+] Stage 2 alerts saved to stage2_alerts.json")





if __name__ == "__main__":

    main()

 
