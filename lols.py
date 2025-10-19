# Python Standard Library Imports
import json
import os
import textwrap
import time

from urllib.request import urlretrieve

# 3rd Party Imports
# None 

# Define URLs for json files of Lolbas and loldrivers
lolbas_url = "https://lolbas-project.github.io/api/lolbas.json"
loldriver_url = "https://www.loldrivers.io/api/drivers.json"

filename = "lolbas.json"
filename2 = "drivers.json"

# Define number of days for age of file
file_age = 14

# Get current time
current_time = time.time()

# Calculate time threshold
threshold_time = current_time - (file_age * 86400)  # 86400 seconds in a day

def get_lolbas_file_endings(lolbas, clipboard_contents):
    lolbas_json = json.loads(lolbas)
    count = 0
    file_endings = set()
    while count < len(lolbas_json):
        file = lolbas_json[count]['Name'].split(".")
        file_end = file[-1].strip()
        file_endings.add(file_end)
        count = count+1
    # Check to see if it ends with one of the lolbas file exensions    
    try:
        for file in file_endings:
            if clipboard_contents.endswith(file):
                return True
            else:
                pass
    except:
        pass

def get_loldriver_file_endings(driver, clipboard_contents):
    loldriver_json = json.loads(driver)
    count = 0
    file_endings = set()
    while count < len(loldriver_json):
        try:
            file = loldriver_json[count]['Tags'][0].split(".")
            file_end = file[1].strip()
            file_endings.add(file_end)
        except:
            pass
        count = count+1

    # Check to see if it ends with one of the loldrier file exensions    
    try:
        for file in file_endings:
            if clipboard_contents.endswith(file):
                return True
            else:
                pass
    except:
        pass

def get_lolbas_json(lolbas_url, filename, file_age, current_time, threshold_time):
    """ Retrieves the json of the lolbas project and returns it.    
    """
    try:
        # get age of LolBas
        lolbas_file_mod_time = os.path.getmtime(filename)
        if lolbas_file_mod_time > threshold_time:
            # Lolbas is newer than specified days
            with open(filename, encoding="utf8") as lolbas_file:
                lolbas = lolbas_file.read()
        else:
            #p Lolbas is older than specified days
            try:
                urlretrieve(lolbas_url, filename)
                with open(filename, encoding="utf8") as lolbas_file:
                    lolbas = lolbas_file.read()
            except:
                    pass    
    except:
        urlretrieve(lolbas_url, filename)
        with open(filename, encoding="utf8") as lolbas_file:
            lolbas = lolbas_file.read()
            
    print("LolBas configured.")            
    return lolbas
    
def get_loldriver_json(loldriver_url, filename2, file_age, current_time, threshold_time):
    """ Retrieves the json of the lolbas project and returns it.    
    """
    try:
        # get age of LolDriver
        loldriver_file_mod_time = os.path.getmtime(filename2)
        if loldriver_file_mod_time > threshold_time:
            # Loldriver is newer than specified days
            with open(filename2, encoding="utf8") as driver_file:
                driver = driver_file.read()
        else:
            # Loldriver is older than specified days
            try:
                urlretrieve(loldriver_url, filename2)
                with open(filename2, encoding="utf8") as driver_file:
                    driver = driver_file.read()
            except:
                pass
    except:
        urlretrieve(loldriver_url, filename2)
        with open(filename2, encoding="utf8") as driver_file:
            driver = driver_file.read()
    
    print("LolDriver configured")    
    return driver
    
def lookup_lolbas(lolbas, clipboard_contents):
    lolbas_json = json.loads(lolbas)
    count = 0
    while count < len(lolbas_json):
            if lolbas_json[count]['Name'] == clipboard_contents:
                print(f"\nName:\t\t\t{lolbas_json[count]['Name']}")
                #print(f"Description:\t\t{lolbas_json[count]['Description']}")
                print("Description:")
                print(textwrap.indent(textwrap.fill(lolbas_json[count]['Description'], width=102), "\t\t\t"))
                if isinstance(lolbas_json[count]['Full_Path'], list):
                #if type(lolbas_json[count]['Full_Path']) == "List":
                    print("Full Path:")
                    for path in lolbas_json[count]['Full_Path']:
                        print(f"\t\t\t{path['Path']}")
                else:
                    print(f"Full Path:\t{lolbas_json[count]['Full_Path']}")
                if isinstance(lolbas_json[count]['Commands'], list):
                     print("Commands:")
                     for command in lolbas_json[count]['Commands']:
                         print(f"\tCommand:\t{command['Command']}")
                         print(f"\tDescription:\t{command['Description']}")
                         print(f"\tUse Case:\t{command['Usecase']}")
                         print(f"\tPrivilege:\t{command['Privileges']}")
                         print(f"\tMITRE:\t\t{command['MitreID']}")
                         print("\n")
                else:
                    print(f"Commands:\t{lolbas_json[count]['Commands']}")
                if isinstance(lolbas_json[count]['Detection'], list):
                    print("IOC's:")
                    for ioc in lolbas_json[count]['Detection']:
                        try:
                            print(f"\tIOC:\t\t{ioc['IOC']}")
                        except:
                            pass
                print(f"URL:\t{lolbas_json[count]['url']}") 
                break
                
            else:
                pass
    
            count += 1
    else:
        print(f"\n\t{clipboard_contents} is not a known LolBin.")
            
def lookup_loldriver(driver, clipboard_contents):
    loldriver_json = json.loads(driver)
    count = 0
    while count < len(loldriver_json):
        if clipboard_contents in loldriver_json[count]['Tags']:
            print(f"\nName:\t\t\t{loldriver_json[count]['Tags'][0]}")
            print(f"Description:")#\t\t{loldriver_json[count]['Commands']['Description']}")
            print(textwrap.indent(textwrap.fill(loldriver_json[count]['Commands']['Description'], width=102), "\t\t\t"))
            print(f"MITRE:\t\t\t{loldriver_json[count]['MitreID']}\n")
            if isinstance(loldriver_json[count]['Commands'], list):
                print("List")
            else:
                print(f"Command:\t\t{loldriver_json[count]['Commands']['Command']}\n")
                print(f"Operating System:\t{loldriver_json[count]['Commands']['OperatingSystem']}")
                print(f"Privileges:\t\t{loldriver_json[count]['Commands']['Privileges']}")
                print(f"Use Case:\t\t{loldriver_json[count]['Commands']['Usecase']}")
                print(f"Resources:\t\t")#{loldriver_json[count]['Resources']}")
                if isinstance(loldriver_json[count]['Resources'], list):
                    for ref in loldriver_json[count]['Resources']:
                        print(f"\t\t\t{ref}")#loldriver_json[count]['Resources'][ref]}")
                else:
                    print(f"\t\t\t{loldriver_json[count]['Resources']}")
                print(f"URL:\t\t\thttps://www.loldrivers.io/drivers/{loldriver_json[count]['Id']}/")  
                break
        else:
            pass
    
        count += 1
    else:
        print(f"\n\t{clipboard_contents} is not a known LolDriver.")
