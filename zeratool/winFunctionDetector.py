import r2pipe
import json
import logging

log = logging.getLogger(__name__)


def getWinFunctions(binary_name):

    winFunctions = {}

    # Initilizing r2 with with function call refs (aac)
    r2 = r2pipe.open(binary_name)
    r2.cmd("aaa")

    functions = [func for func in json.loads(r2.cmd("aflj"))] #j in r2 is for json format

    # Check for function that gives us system(/bin/sh)
    for func in functions:
        if "system" in str(func["name"]):
            system_name = func["name"]
 
            # Get XREFs, or cross references i.e. where theses addresses are being called
            refs = [
                func for func in json.loads(r2.cmd("axtj @ {}".format(system_name)))
            ]
            # for ref in refs:
            #     if "fcn_name" in ref:
            #         winFunctions[ref["fcn_name"]] = ref

    # Check for function that reads flag.txt
    # Then prints flag.txt to STDOUT
    known_flag_names = ["flag", "pass"]

    strings = [string for string in json.loads(r2.cmd("izj"))]
    for string in strings:
        value = string["string"]
        if any([x in value for x in known_flag_names]):
            address = string["vaddr"]

            # Get XREFs
            refs = [func for func in json.loads(r2.cmd("axtj @ {}".format(address)))]
            for ref in refs:
                if "fcn_name" in ref:
                    winFunctions[ref["fcn_name"]] = ref

    for k, v in list(winFunctions.items()):
        log.info("[+] Found win function {}".format(k))

    return winFunctions
