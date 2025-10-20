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

def sanitize_url(suspect_url):
    url_list = suspect_url.split(":")
    if url_list[0] == 'http':
        sanitized_url = 'hxxp:' + url_list[1]
    elif url_list[0] == 'https':
        sanitized_url = 'hxxps:' + url_list[1]
    else:
        sanitized_url = 'hxxp:' + suspect_url
    return sanitized_url

def print_lists(attribute_list, name):
    """
    Takes a dictionary containing a single key value pair.  This usually comes from the JSON output of VirustTotal or ALienVault OTX.  
    Example Usage:  print_lists(vt_url_response['data']['attributes']['tags'],"Tags")


    """
    try:
        attribute_list
    except:
        pass
    else:
        if len(attribute_list) <= 5:
            print("\t" + color.UNDERLINE + name + color.END + ":")
            for line in attribute_list:
                print("\t   " + line)
        else:
            count = 0
            for line in attribute_list:
                if count <= 4:
                    print("\t   " + line)
                    count = count + 1

