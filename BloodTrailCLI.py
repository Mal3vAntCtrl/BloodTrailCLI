#!/usr/bin/env python3

import os
import sys
import json
import tempfile
import zipfile
import shutil

# ---------------------------
# ASCII Banner
# ---------------------------
def ascii_banner():
    banner = r"""
 ____  _                 _ _____     _ _ 
| __ )| | ___   ___   __| |_   _| __(_| |
|  _ \| |/ _ \ / _ \ / _` | | || '__| | |
| |_) | | (_) | (_) | (_| | | || (_)| | |
|____/|_|\___/ \___/ \__,_| |_||_|__|_|_|
             BloodTrailCLI
    """
    print(banner)
    print("Welcome to 🩸 BloodTrailCLI — Active Directory Relationship Mapper\n")

# ---------------------------
# SID Map Builder
# ---------------------------

def build_sid_map(json_files):
    sid_map = {}
    for fpath in json_files:
        try:
            with open(fpath, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            for entry in data.get("data", []):
                props = entry.get("Properties", {})
                sid = props.get("objectid") or entry.get("ObjectIdentifier")
                name = props.get("name")
                if sid and name:
                    sid_map[sid] = name
        except Exception as e:
            print(f"[!] Failed to build SID map from {fpath}: {e}")
    return sid_map

# ---------------------------
# Relationship Parsers
# ---------------------------

def parse_computers_acl(json_path):
    relationships = []
    try:
        with open(json_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        for entry in data.get("data", []):
            target = entry.get("Properties", {}).get("name")
            for ace in entry.get("Aces", []):
                src = ace.get("PrincipalSID")
                rel = ace.get("RightName")
                if src and target and rel:
                    relationships.append((src, target, rel))
    except Exception as e:
        print(f"[!] Error parsing {json_path}: {e}")
    return relationships

def parse_groups(json_path):
    relationships = []
    try:
        with open(json_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        for group in data.get("data", []):
            group_name = group.get("Properties", {}).get("name")
            for member in group.get("Members", []):
                member_sid = member.get("ObjectIdentifier")
                if member_sid and group_name:
                    relationships.append((member_sid, group_name, "MemberOf"))
    except Exception as e:
        print(f"[!] Error parsing {json_path}: {e}")
    return relationships

def parse_domains(json_path):
    relationships = []
    try:
        with open(json_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        for domain in data.get("data", []):
            src = domain.get("Properties", {}).get("name")
            for trust in domain.get("Trusts", []):
                dst = trust.get("TargetDomainName")
                if src and dst:
                    relationships.append((src, dst, "Trusts"))
    except Exception as e:
        print(f"[!] Error parsing {json_path}: {e}")
    return relationships

def parse_gpos(json_path):
    relationships = []
    try:
        with open(json_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        for gpo in data.get("data", []):
            gpo_name = gpo.get("Properties", {}).get("name")
            for link in gpo.get("Links", []):
                target = link.get("Target")
                if gpo_name and target:
                    relationships.append((gpo_name, target, "LinkedTo"))
    except Exception as e:
        print(f"[!] Error parsing {json_path}: {e}")
    return relationships

def parse_users(json_path):
    relationships = []
    try:
        with open(json_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        for user in data.get("data", []):
            user_name = user.get("Properties", {}).get("name")
            for delegate in user.get("AllowedToDelegate", []):
                relationships.append((user_name, delegate, "CanDelegateTo"))
    except Exception as e:
        print(f"[!] Error parsing {json_path}: {e}")
    return relationships

def parse_ous(json_path):
    relationships = []
    try:
        with open(json_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        for ou in data.get("data", []):
            name = ou.get("Properties", {}).get("name")
            if name:
                relationships.append((name, "ActiveDirectory", "OU"))
    except Exception as e:
        print(f"[!] Error parsing {json_path}: {e}")
    return relationships

# ---------------------------
# ZIP Loader
# ---------------------------

def load_sharphound_zip(zip_path):
    relationships = []
    temp_dir = tempfile.mkdtemp()

    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_dir)

        json_files = []
        for root, _, files in os.walk(temp_dir):
            for file in files:
                if file.lower().endswith(".json"):
                    json_files.append(os.path.join(root, file))

        print(f"[+] Found {len(json_files)} JSON files in the ZIP.\n")

        sid_map = build_sid_map(json_files)

        for jf in json_files:
            name = os.path.basename(jf).lower()

            if "computers" in name:
                relationships += parse_computers_acl(jf)
            elif "groups" in name:
                relationships += parse_groups(jf)
            elif "domains" in name:
                relationships += parse_domains(jf)
            elif "gpos" in name:
                relationships += parse_gpos(jf)
            elif "users" in name:
                relationships += parse_users(jf)
            elif "ous" in name:
                relationships += parse_ous(jf)
            else:
                continue  # silently skip

        shutil.rmtree(temp_dir)
        return relationships, sid_map

    except Exception as e:
        print(f"[!] Failed to process ZIP: {e}")
        shutil.rmtree(temp_dir)
        return [], {}

# ---------------------------
# Display Relationships
# ---------------------------

def display_relationships(relationships, sid_map):
    if not relationships:
        print("⚠️  No usable relationships found.")
        return

    print("\n[+] Discovered Relationships:")
    print("-" * 80)
    for src, dst, rel in relationships:
        src_display = sid_map.get(src, src)
        dst_display = sid_map.get(dst, dst)
        print(f"{src_display:35} -- {rel:20} --> {dst_display}")
    print("-" * 80)
    print(f"[+] Total: {len(relationships)} relationships\n")

# ---------------------------
# Main Menu
# ---------------------------

def main_menu():
    while True:
        ascii_banner()
        print("1️⃣  Load SharpHound ZIP and Map Relationships")
        print("2️⃣  Exit")
        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            zip_path = input("\n📂 Enter path to SharpHound ZIP: ").strip()
            if not os.path.exists(zip_path):
                print("❌ File not found.")
                continue

            relationships, sid_map = load_sharphound_zip(zip_path)
            display_relationships(relationships, sid_map)
            input("🔁 Press Enter to return to menu...")

        elif choice == "2":
            print("👋 Exiting BloodTrailCLI.")
            sys.exit(0)

        else:
            print("❌ Invalid selection.\n")

# ---------------------------
# Entry Point
# ---------------------------

if __name__ == "__main__":
    main_menu()
