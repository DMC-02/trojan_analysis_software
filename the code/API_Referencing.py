import os
import csv
import argparse
import requests

def api_call_VT(md5_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{md5_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_data = response.json()
            stats = json_data["data"]["attributes"]["last_analysis_stats"]
            info = {
                "Source": "VirusTotal",
                "MD5": md5_hash,
                "Malicious": stats["malicious"],
                "Suspicious": stats["suspicious"],
                "Undetected": stats ["undetected"],
            }
            return info
        elif response.status_code == 404:
            return {"Source": "VirusTotal", "Error": "Hash not found"}
        else:
            return {"Source": "VirusTotal", "Error": f"API error {response.status_code}"}
    except Exception as e:
        return {"Source": "VirusTotal", "Error": str(e)}
