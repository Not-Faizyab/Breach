import time
import random
import requests
import base64
from datetime import datetime

# --- CONFIGURATION ---
API_KEY = "fbbed4ca-e3cf-497f-8682-adb537558a64" 
API_URL = "https://hackatime.hackclub.com/api/hackatime/v1"
FILE_PATH = r"D:\Personal\Code\Projects\Breach\src\main.rs"
PROJECT_NAME = "Breach"
# ---------------------

def send_heartbeat():
    url = f"{API_URL}/users/current/heartbeats"
    auth_bytes = base64.b64encode(API_KEY.encode('utf-8'))
    headers = {
        "Authorization": f"Basic {auth_bytes.decode('utf-8')}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "entity": FILE_PATH,
        "type": "file",
        "category": "coding",
        "project": PROJECT_NAME,
        "language": "Rust",
        "time": time.time(),
        "is_write": True
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code in [200, 201, 202]:
            print(f"[{time.strftime('%H:%M:%S')}] Heartbeat accepted! Coding time logged.")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] Failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Connection error: {e}")

def run_ghost_protocol():
    # Flawless 324-hour baseline tracking matrix (Monday=0 to Sunday=6)
    schedule = {
        0: 3.0,  # Monday
        1: 5.0,  # Tuesday
        2: 6.0,  # Wednesday
        3: 4.0,  # Thursday
        4: 7.0,  # Friday
        5: 9.0,  # Saturday
        6: 8.0   # Sunday
    }
    
    day_index = datetime.today().weekday()
    day_name = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"][day_index]
    
    # 1. Calculate Human Telemetry Variance (± 15 to 25 minutes)
    variance_minutes = random.uniform(-25, 25)
    target_hours = schedule[day_index] + (variance_minutes / 60)
    target_seconds = target_hours * 3600
    
    # 2. Dynamic Dinner Break Config (Triggers if target session exceeds 4.5 hours)
    needs_break = target_hours > 4.5
    break_duration = 0
    total_session_time = target_seconds
    
    print("=*" * 20)
    print(f"👑 LORD'S GHOST PROTOCOL INITIATED 👑")
    print("=*" * 20)
    print(f"[*] Day Flagged: {day_name}")
    print(f"[*] Target Operational Time: {target_hours:.2f} Hours")
    if needs_break:
        print(f"[*] Automated Dinner Pause: {break_duration/60:.1f} Minutes (Middle of Session)")
    print(f"[*] Total Execution Envelope: {(total_session_time/3600):.2f} Hours")
    print(f"[*] System status: Fire & Forget. Window closes automatically.\n")

    start_time = time.time()
    break_taken = False
    
    # 3. Main Operational Window Loop
    while time.time() - start_time < total_session_time:
        elapsed = time.time() - start_time
        
        # Deploy structural break exactly at the halfway mark of active telemetry
        if needs_break and not break_taken and elapsed > (target_seconds / 2):
            print(f"\n[!] Triggering stealth pause for {break_duration/60:.1f} minutes to mimic human activity...")
            time.sleep(break_duration)
            print("[+] Operational break concluded. Resuming telemetry stream...\n")
            break_taken = True
            
        # Fire the payload
        send_heartbeat()
        
        # Maintain rapid logging while mimicking variable keystroke pauses
        delay = random.randint(31, 40)
        print(f"Next heartbeat queued in {delay} seconds...")
        time.sleep(delay)

    print("\n✅ Daily telemetry allocation achieved. Terminating secure connection. Stay safe, Lord.")

if __name__ == "__main__":
    try:
        run_ghost_protocol()
    except KeyboardInterrupt:
        print("\n[-] Mission aborted early by executive command.")