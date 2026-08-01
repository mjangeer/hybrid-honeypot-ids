import json

from collections import defaultdict



failed_logins = defaultdict(int)

commands = defaultdict(list)



with open("/home/cowrie/cowrie/var/log/cowrie/cowrie.json") as f:

    for line in f:

        try:

            event = json.loads(line)

        except:

            continue



        if event.get("eventid") == "cowrie.login.failed":

         session_id = event.get("session")

         if session_id:

              failed_logins[session_id] += 1



        if event.get("eventid") == "cowrie.command.input":

            session_id = event.get("session")

            if session_id:

                commands[session_id].append(event.get("input"))



print("Failed login attempts:")

for ip, count in failed_logins.items():

    print(ip, count)



print("#nCommands executed:")

for ip, cmds in commands.items():

    print(ip, cmds)


import json





# Build sessions dictionary

sessions = {}

for ip in set(list(failed_logins.keys()) + list(commands.keys())):

       sessions[ip] = {

           "failed_logins": failed_logins.get(ip, 0),

           "commands": commands.get(ip, [])

       }

   

   # Save to JSON file

output_file = "session_features.json"

with open(output_file, "w") as out:

 json.dump(sessions, out, indent=4)

   

print(f"#n[+] Extracted features saved to {output_file}")
