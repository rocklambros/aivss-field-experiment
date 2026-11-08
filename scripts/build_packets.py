#!/usr/bin/env python3
"""
Script to build rater packets for each finding in the AIVSS experiment.
Each packet contains the finding description, code excerpts, lab profile, rubric text, 
and scoring instructions for the raters.
"""

import json
import os
from pathlib import Path

def load_findings():
    """Load the findings from the findings.json file"""
    with open('findings.json', 'r') as f:
        return json.load(f)

def load_lab_profiles():
    """Load lab profiles from the labs directory"""
    profiles = {}
    for lab_name in ['finbot-ctf-demo', 'agent-sec-lab', 'damn-vulnerable-ai-agent']:
        profile_path = f'labs/{lab_name}/profile.json'
        if os.path.exists(profile_path):
            with open(profile_path, 'r') as f:
                profiles[lab_name] = json.load(f)
    return profiles

def load_rubric():
    """Load rubric text from rubric.txt"""
    with open('rubric/rubric.txt', 'r') as f:
        return f.read()

def create_packet_template(finding, lab_name, lab_profile, rubric_text):
    """
    Create a rater packet template for a single finding
    """
    packet = {
        "finding_id": finding["id"],
        "title": finding["title"],
        "lab": lab_name,
        "path_id": finding["path_id"],
        "path_group": finding.get("path_group", None),
        "asi_category": finding.get("asi_category", None),
        
        # Finding details
        "entry_point": finding["entry_point"],
        "steps": finding["steps"],
        "sink": finding["sink"],
        "impact": finding["impact"],
        "preconditions": finding["preconditions"],
        "source_citations": finding["source_citations"],
        "code_citations": finding["code_citations"],
        
        # Lab context
        "lab_label": finding.get("lab_label", ""),
        "lab_severity": finding.get("lab_severity", None),
        "lab_difficulty": finding.get("lab_difficulty", None),
        
        # Exploit information
        "poc": finding.get("poc", {}),
        
        # Lab profile information
        "lab_profile": lab_profile,
        
        # Rubric text for scoring
        "rubric_text": rubric_text,
        
        # Scoring instructions (these will be filled in by the raters)
        "scoring_instructions": {
            "cvss_vector": "A CVSS v4.0 base vector (all 11 base metrics), scored for the lab's default configuration as documented, using FIRST's metric definitions. The agent application is the vulnerable system. Downstream tools, data stores, and other agents are subsequent systems (SC, SI, SA).",
            "aivss_vector": "An `AIVSS:1.0/LC:_/CP:_/AP:_/RH:_/ES:_` vector, with a rationale, evidence references (file and line), and a confidence (low, medium, or high) for every metric.",
            "rh_facts": "The RH facts (`reachable_proxy`, `isolation_verified`, `verified_episodes`, `episodes_reviewed`, `locus`), consistent with the calculator's `classify_rh()` rules.",
            "bod_2604_track": "Answers for `automatable` and `technical_impact` for the BOD 26-04 analogy track, with a rationale.",
            "applicability": "The agentic applicability answers for the agent involved, under the dual-scoring rule of Settled Decision 2."
        }
    }
    
    return packet

def main():
    """Main function to build all rater packets"""
    print("Building rater packets...")
    
    # Load data
    findings_data = load_findings()
    lab_profiles = load_lab_profiles()
    rubric_text = load_rubric()
    
    # Create packets directory
    os.makedirs('packets', exist_ok=True)
    
    # Counter for progress
    total_findings = 0
    packets_created = 0
    
    # Process findings from each lab
    for lab_name, lab_data in findings_data['labs'].items():
        print(f"Processing {lab_name}...")
        lab_profile = lab_profiles.get(lab_name, {})
        
        if 'findings' in lab_data:
            for finding in lab_data['findings']:
                total_findings += 1
                
                # Create packet
                packet = create_packet_template(finding, lab_name, lab_profile, rubric_text)
                
                # Save packet to file
                packet_filename = f"packets/{finding['id']}.json"
                with open(packet_filename, 'w') as f:
                    json.dump(packet, f, indent=2)
                
                packets_created += 1
                print(f"  Created packet for {finding['id']}")
    
    print(f"\nCompleted: {packets_created}/{total_findings} packets created")

if __name__ == "__main__":
    main()