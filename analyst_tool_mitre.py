import json
import logging
import os
import re
import time
import asyncio
from attackcti import attack_client
from IPython.display import display, Markdown

# Custom Utility Imports
from analyst_tool_utilities import color

class AsyncAnalystToolMitre:
    def __init__(self, terminal=1):
        self.terminal = terminal
        self.mitre_tactics = []
        self.mitre_techniques = []
        self.tactics_filename = "enterprise_tactics.json"
        self.techniques_filename = "mitre_techniques.json"
        self.lift = self._initialize_mitre()
        
        # Load data on init
        self.mitre_tactics = self._load_data(self.tactics_filename, "tactics")
        self.mitre_techniques = self._load_data(self.techniques_filename, "techniques")

    def _initialize_mitre(self):
        logging.getLogger('taxii2client').setLevel(logging.CRITICAL)
        try:
            return attack_client()
        except:
            return None

    def _load_data(self, filename, data_type):
        """Maintains your original file age logic/JSON loading."""
        threshold = time.time() - (90 * 86400)
        
        if os.path.exists(filename) and os.path.getmtime(filename) > threshold:
            with open(filename, encoding="utf8") as f:
                return json.load(f)
        
        # Fallback to API if file is missing or old
        if self.lift:
            try:
                if data_type == "tactics":
                    data = self.lift.get_enterprise_tactics()
                else:
                    data = [json.loads(t.serialize()) for t in self.lift.get_enterprise_techniques()]
                
                with open(filename, "w") as f:
                    json.dump(data, f)
                return data
            except Exception as e:
                print(f"Error refreshing MITRE {data_type}: {e}")
        
        # Fallback to existing file if API fails
        if os.path.exists(filename):
            with open(filename, encoding="utf8") as f:
                return json.load(f)
        return []

    async def lookup(self, indicator):
        """The unified interface for analyst.py."""
        # This mirrors your is_mitre_tactic_technique_sub_tecnique logic
        mitre_tactic_regex = '^TA000[1-9]|TA001[0-1]|TA004[0,2-3]$'
        mitre_technique_regex = '^T[0-9]{4}$'
        mitre_sub_technique_regex = '^T[0-9]{4}\.[0-9]{3}$'

        if re.match(mitre_tactic_regex, indicator):
            self._print_tactic(indicator)
        elif re.match(mitre_technique_regex, indicator):
            self._print_technique(indicator)
        elif re.match(mitre_sub_technique_regex, indicator):
            parent = indicator.split(".")[0]
            self._print_sub_technique(indicator, parent)

    # --- Print Methods (Preserving your original formatting) ---
    
    def _print_tactic(self, mitre_id):
        for t in self.mitre_tactics:
            for ref in t.get('external_references', []):
                if ref.get('external_id') == mitre_id:
                    print(f"\n\n\nMitre Tactic: {mitre_id}")
                    print(f"{color.BOLD}{t['name']}:{color.END}\n{ref['url']}\n")
                    self._output_format(t['description'])

    def _print_technique(self, mitre_id):
        for tech in self.mitre_techniques:
            for ref in tech.get('external_references', []):
                if ref.get('external_id') == mitre_id:
                    self._render_tech_info(tech, ref)

    def _print_sub_technique(self, sub_id, parent_id):
        for tech in self.mitre_techniques:
            for ref in tech.get('external_references', []):
                if ref.get('external_id') == sub_id:
                    print(f"\nMitre Tactic: {tech['kill_chain_phases'][0]['phase_name'].title()}")
                    self._print_technique(parent_id)
                    print(f"Mitre Sub-Technique: {sub_id}\n{ref['url']}")
                    self._render_tech_info(tech, ref)

    def _render_tech_info(self, tech, ref):
        print(f"{color.BOLD}{tech['name']}{color.END}")
        self._output_format(tech['description'])
        print(f"\n{color.BOLD}Detection:{color.END}")
        self._output_format(tech.get('x_mitre_detection', 'No detection info found.'))

    def _output_format(self, content):
        if self.terminal == 0:
            display(Markdown(content))
        else:
            print(content)
