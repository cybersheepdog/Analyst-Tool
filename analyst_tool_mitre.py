# Python Standard Library Imports
import json
import logging
import re

# 3rd Party Imports
import logging
from attackcti import attack_client
from pandas import *
from IPython.display import display, Markdown

# Declare Regex to determin if MITRE or not
mitre_regex = '^T[0-9]{4}\.[0-9]{3}$|^TA000[1-9]|TA001[0-1]|TA004[0,2-3]$|T[0-9]{4}$'

# List to store Mitre ATT&CK techniques
mitre_techniques = []

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

def initialize_mitre(mitre_techniques):
    logging.getLogger('taxii2client').setLevel(logging.CRITICAL)
    lift = attack_client()

    print("Initializing the Mitre ATT&CK Module.  Please be patient.")
    try:
        enterprise_tactics = lift.get_enterprise_tactics()
        enterprise_techniques = lift.get_enterprise_techniques()
        for t in enterprise_techniques:
            mitre_techniques.append(json.loads(t.serialize()))
    except:
        print("Failed to initalize the Mitre ATT&CK module!")
    else:
        print("Mitre ATT&CK Initalized.")

def is_mitre_tactic_technique_sub_tecnique(mitre, enterprise_tactics, mitre_techniques, terminal):
    mitre_tactic_regex = '^TA000[1-9]|TA001[0-1]|TA004[0,2-3]$'
    mitre_technique_regex = '^T[0-9]{4}$'
    mitre_sub_technique_regex = '^T[0-9]{4}\.[0-9]{3}$'

    if re.match(mitre_tactic_regex, mitre):
        mitre_tactic = mitre
        print_mitre_tactic(mitre_tactic, enterprise_tactics, terminal)
    elif re.match(mitre_technique_regex, mitre):
        mitre_technique = mitre
        print_mitre_technique(mitre_technique, mitre_techniques, terminal)
    elif re.match(mitre_sub_technique_regex, mitre):
        mitre_sub_technique = mitre
        mitre = mitre.split(".")
        mitre_technique = mitre[0]
        print_mitre_sub_technique(mitre_sub_technique, mitre_techniques, mitre_technique, terminal)
    else:
        pass

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

def print_mitre_tactic(mitre_tactic, enterprise_tactics, terminal):
    """Searches through Mitre ATT&CK for a tactic and pulls the inforation out and prints to the screen.

    Requried Parameters:
         mitre_tactic - derived from the is_mitre_tactic_technique_sub_tecnique function
         enterprise - ditionary of mitre att&ck objects derived from mitre initializaiton in the analyst function

    Optional Parameter:
         terminal - leave set to 0 to display markdown in jupyter notebook
                    set to 1 in the analyst_tool.py file to disable parkdown for displaying in terminal

    """

    for tactics in enterprise_tactics:
        for tactic in tactics['external_references']:
            if tactic['external_id'] == mitre_tactic:
                print("\n\n\nMitre Tactic: " + mitre_tactic)
                print(color.BOLD + tactics['name'] + ":\t" + color.END + '\n')
                if terminal == 0:
                    display(Markdown(tactics['description']))
                else:
                    print(tactics['description'])
                print("\n" + tactic['url'])

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
