import os
import csv
import argparse
import requests
import datetime
from collections import Counter

def api_call_VT(md5_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{md5_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_data = response.json()
            stats = json_data["data"]["attributes"]["last_analysis_stats"]
            attributes = json_data["data"]["attributes"]
            detections = attributes.get("last_analysis_results")

            # Trojan detection
            name_counter = Counter()
            for engine, result in detections.items():
                if result.get("category") == "malicious":
                    name = result.get("result")
                    if name and "trojan" in name.lower():
                        name_counter[name] += 1
            if name_counter:
                most_common_name, count = name_counter.most_common(1)[1]
                malware_name = f"{most_common_name} (reported by {count} engines)"
                is_trojan = True
            else:
                malware_name = "No trojan detected, yaey"
                is_trojan = False
            info = {
                "Source": "VirusTotal",
                "MD5": md5_hash,
                "Type": attributes["type_description"],
                "Size (bytes)": attributes["size"],
                "First Appearance": datetime.datetime.utcfromtimestamp(attributes["first_submission_date"]).strftime('%d-%m-%Y %H:%H:%S'),
                "First Appearance": datetime.datetime.utcfromtimestamp(attributes["first_submission_date"]).strftime('%d-%m-%Y %H:%H:%S'),
                "Malicious": stats["malicious"],
                "Suspicious": stats["suspicious"],
                "Undetected": stats ["undetected"],
                "Is Trojan": "Yes" if is_trojan else "No",
                "Malware Name": malware_name,
            }
            return info
        elif response.status_code == 404:
            return {"Source": "VirusTotal", "Error": "Hash not found"}
        else:
            return {"Source": "VirusTotal", "Error": f"API error {response.status_code}"}
    except Exception as e:
        return {"Source": "VirusTotal", "Error": str(e)}
