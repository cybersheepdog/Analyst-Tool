# Python Standard Library Imports
import json
import logging
import os
import re
import time

# 3rd Party Imports
import logging
from attackcti import attack_client
from pandas import *
from IPython.display import display, Markdown

# Declare Regex to determin if MITRE or not
mitre_regex = '^T[0-9]{4}\.[0-9]{3}$|^TA000[1-9]|TA001[0-1]|TA004[0,2-3]$|T[0-9]{4}$'

# List to store Mitre ATT&CK techniques
mitre_techniques = []
mitre_tactics = []

# Json files for Mitre tactics & techniques
tactics_filename = "enterprise_tactics.json"
techniques_filename = "mitre_techniques.json"

# Define number of days for age of file
mitre_file_age = 90

# Get current time
mitre_current_time = time.time()

# Calculate time threshold
mitre_threshold_time = mitre_current_time - (mitre_file_age * 86400)  # 86400 seconds in a day

class color:
   """Used to to color code text ouptut in order to highlight key pieces of information.

      Usage Example:  print(color.PURPLE + 'Hello World' + color.END)

   """
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[31m'
   ORANGE = '\033[33m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def get_mitre_tactics_json(tactics_filename, mitre_file_age, mitre_current_time, mitre_threshold_time, lift):
    """ Retrieves the locally stored json of mitre tactics, checks the age and
    returns it.    
    """
    try:
        # get age of tactics
        tactics_file_mod_time = os.path.getmtime(tactics_filename)
        if tactics_file_mod_time > mitre_threshold_time:
            with open(tactics_filename, encoding="utf8") as tactics_file:
                tactics = json.loads(tactics_file.read())
        else:
            # tactics is older than specified days
            try:
                if lift != 0:
                    tactics = lift.get_enterprise_tactics()
                    with open("enterprise_tactics.json", "w") as file:
                        json.dump(tactics, file)
                else:
                    with open(tactics_filename, encoding="utf8") as tactics_file:
                        tactics = json.loads(tactics_file.read())
            except:
                with open(tactics_filename, encoding="utf8") as tactics_file:
                    tactics = json.loads(tactics_file.read())
    except:
        # Tactics file does not exist.  Attepmt to get tactics from API and save to file
        if lift != 0:
            tactics = lift.get_enterprise_tactics()
            with open(tactics_filename, "w") as file:
                json.dump(tactics, file)
        else:
            with open(tactics_filename, encoding="utf8") as tactics_file:
                tactics = json.loads(tactics_file.read())
        
    return tactics

def get_mitre_technique(mitre_technique, mitre_techniques):
    for techniques in mitre_techniques:
        for technique in techniques['external_references']:
            try:
                technique['external_id'] == mitre_technique
            except:
                pass
            else:
                if technique['external_id'] == mitre_technique:
                    print("{:<23} {}".format("Mitre Technique:",techniques['name']))

def get_mitre_techniques_json(techniques_filename, mitre_file_age, mitre_current_time, mitre_threshold_time, lift):
    """ Retrieves the locally stored json of mitre techniques, checks the age and
    returns it.    
    """
    try:
        # get age of techniques
        techniques_file_mod_time = os.path.getmtime(techniques_filename)
        if techniques_file_mod_time > mitre_threshold_time:
            with open(techniques_filename, encoding="utf8") as techniques_file:
                techniques = json.loads(techniques_file.read())
        else:
            # techniques is older than specified days
            try:
                if lift != 0:
                    enterprise_techniques = lift.get_enterprise_techniques()
                    for tech in enterprise_techniques:
                        mitre_techniques.append(json.loads(tech.serialize()))
                    with open(techniques_filename, "w") as file:
                        json.dump(mitre_techniques, file)
                else:
                    with open(techniques_filename, encoding="utf8") as techniques_file:
                        techniques = json.loads(techniques_file.read())
            except:
                with open(techniques_filename, encoding="utf8") as techniques_file:
                    techniques = json.loads(techniques_file.read())
    except:
        # File does not already exist so get it from API and write to disk
        try:
            if lift != 0:
                enterprise_techniques = lift.get_enterprise_techniques()
                for tech in enterprise_techniques:
                    mitre_techniques.append(json.loads(tech.serialize()))
                with open(techniques_filename, "w") as file:
                    json.dump(mitre_techniques, file)
            else:
                with open(techniques_filename, encoding="utf8") as techniques_file:
                    mitre_techniques = json.loads(techniques_file.read())
        
                return mitre_techniques
        except:
            print("Error getting MITRE Techniques")
        
    return techniques

def initialize_mitre():
    print("Initializing the Mitre ATT&CK Module.  Please be patient.")
    logging.getLogger('taxii2client').setLevel(logging.CRITICAL)
    try:
        lift = attack_client()
    except:
        lift = 0

    return lift

def is_mitre_tactic_technique_sub_tecnique(mitre, mitre_tactics, mitre_techniques, terminal):
    mitre_tactic_regex = '^TA000[1-9]|TA001[0-1]|TA004[0,2-3]$'
    mitre_technique_regex = '^T[0-9]{4}$'
    mitre_sub_technique_regex = '^T[0-9]{4}\.[0-9]{3}$'

    if re.match(mitre_tactic_regex, mitre):
        mitre_tactic = mitre
        print_mitre_tactic(mitre_tactic, mitre_tactics, terminal)
    elif re.match(mitre_technique_regex, mitre):
        mitre_technique = mitre
        print_mitre_technique(mitre_technique, mitre_techniques, terminal)
    elif re.match(mitre_sub_technique_regex, mitre):
        mitre_sub_technique = mitre
        mitre = mitre.split(".")
        mitre_technique = mitre[0]
        print_mitre_sub_technique(mitre_sub_technique, mitre_techniques, mitre_technique, terminal)
    else:
        print("Not a MITRE Tactic, Technique or Sub-Technique")

def print_mitre_sub_technique(mitre_sub_technique, mitre_techniques, mitre_technique, terminal):
    """Searches through Mitre ATT&CK for a Sub-Technique and pulls the inforation out and prints to the screen.

    Requried Parameters:
         mitre_sub_technique - derived from the is_mitre_tactic_technique_sub_tecnique function
         mitre_techniques - list of mitre att&ck techniques derived from mitre initializaiton in the analyst function
         mitre_techniqe - derived from the is_mitre_tactic_technique_sub_tecnique function

    Optional Parameter:
         terminal - leave set to 0 to display markdown in jupyter notebook
                    set to 1 in the analyst_tool.py file to disable parkdown for displaying in terminal

    """
    for techniques in mitre_techniques:
        for technique in techniques['external_references']:
        #print(technique['external_id'])
            try:
                technique['external_id'] == mitre_sub_technique
            except:
                pass
            else:
                if technique['external_id'] == mitre_sub_technique:
                    print("\n\n\n{:<23} {}".format("Mitre Tactic:",techniques['kill_chain_phases'][0]['phase_name'].title()))
                    get_mitre_technique(mitre_technique, mitre_techniques)
                    print("Mitre Sub-Technique:\t" + technique['external_id'])
                    print(technique['url'] + "\n")
                    print(color.BOLD + techniques['name'] + color.END)
                    if terminal == 0:
                        display(Markdown(techniques['description']))
                    else:
                        print(techniques['description'])
                    print("\n")
                    print(color.BOLD + "Detection:" + color.END)
                    if terminal == 0:
                        display(Markdown(techniques['x_mitre_detection']))
                    else:
                        print(techniques['x_mitre_detection'])

def print_mitre_tactic(mitre_tactic, mitre_tactics, terminal):
    """Searches through Mitre ATT&CK for a tactic and pulls the inforation out and prints to the screen.

    Requried Parameters:
         mitre_tactic - derived from the is_mitre_tactic_technique_sub_tecnique function
         enterprise - ditionary of mitre att&ck objects derived from mitre initializaiton in the analyst function

    Optional Parameter:
         terminal - leave set to 0 to display markdown in jupyter notebook
                    set to 1 in the analyst_tool.py file to disable parkdown for displaying in terminal

    """
    for tactics in mitre_tactics:
        for tactic in tactics['external_references']:
            if tactic['external_id'] == mitre_tactic:
                print("\n\n\nMitre Tactic: " + mitre_tactic)
                print(color.BOLD + tactics['name'] + ":\t" + color.END)
                print(tactic['url'] + '\n')
                if terminal == 0:
                    display(Markdown(tactics['description']))
                else:
                    print(tactics['description'])

def print_mitre_technique(mitre_technique, mitre_techniques, terminal):
    """Searches through Mitre ATT&CK for a Technique and pulls the inforation out and prints to the screen.

    Requried Parameters:
         mitre_techniqe - derived from the is_mitre_tactic_technique_sub_tecnique function
         mitre_techniques - list of mitre att&ck techniques derived from mitre initializaiton in the analyst function

    Optional Parameter:
         terminal - leave set to 0 to display markdown in jupyter notebook
                    set to 1 in the analyst_tool.py file to disable parkdown for displaying in terminal

    """

    for techniques in mitre_techniques:
        for technique in techniques['external_references']:
        #print(technique['external_id'])
            try:
                technique['external_id'] == mitre_technique
            except:
                pass
            else:
                if technique['external_id'] == mitre_technique:
                    print("\n\n\n{:<23} {}".format("Mitre Tactic:",techniques['kill_chain_phases'][0]['phase_name'].title()))
                    print("Mitre Technique:\t" + technique['external_id'])
                    print(technique['url'] + "\n")
                    print(color.BOLD + techniques['name'] + color.END)
                    if terminal == 0:
                        display(Markdown(techniques['description']))
                    else:
                        print(techniques['description'])
                    print("\n")
                    print(color.BOLD + "Detection:" + color.END)
                    if terminal == 0:
                        display(Markdown(techniques['x_mitre_detection']))
                    else:
                        print(techniques['x_mitre_detection'])

def verify_mitre_initialized(mitre_techniques, mitre_tactics):
    if mitre_techniques is None:
        print("Mitre not initialized")
    elif len(mitre_techniques) == 0:
        print("Mitre not initialized")
    elif mitre_tactics is None:
        print("Mitre not initialized")
    elif len(mitre_tactics) == 0:
        print("Mitre not initialized")
    else:
        print("MITRE Initialized.")
