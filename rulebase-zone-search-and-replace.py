###############################################################################
#
# Script:       rulebase-zone-search-and-replace.py
#
# Author:       Chris Goodwin <chrisgoodwins@gmail.com>
#
# Description:  Search and replace source and destination zones in rulebases
#               on firewall or Panorama device group. Security, NAT,
#               decryption, and authentication rulebases are supported. Search
#               functionality is handled via regex string. The script pushes
#               changes via API call, first by adding the new zones via a single
#               call (if the call is over the 6K character limit, then it
#               splits it into multiple calls), then by removing zones via
#               individual calls. Please keep in mind that a high number of API
#               calls could have an impact on the management plane of your PAN
#               device. The script can optionally be run offline against a
#               Panorama or firewall XML config file.
#
# Usage:        rulebase-zone-search-and-replace.py
#               or
#               rulebase-zone-search-and-replace.py <config.xml>
#
# Requirements: requests
#
# Python:       Version 3
#
###############################################################################
###############################################################################


import os
import sys
import getpass
import re
import time
from xml.etree import ElementTree as ET
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    raise ValueError('requests support not available, please install module')

###############################################################################
###############################################################################


# Prompts the user to enter an address, then checks it's validity
def getfwipfqdn():
    while True:
        fwipraw = input('\nPlease enter Panorama/firewall IP or FQDN: ')
        ipr = re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', fwipraw)
        fqdnr = re.match(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', fwipraw)
        if ipr:
            break
        elif fqdnr:
            break
        else:
            print('\nThere was something wrong with your entry. Please try again...\n')
    return fwipraw


# Prompts the user to enter a username and password
def getCreds():
    while True:
        username = input('Please enter your user name: ')
        usernamer = re.match(r'^[\w-]{3,24}$', username)
        if usernamer:
            password = getpass.getpass('Please enter your password: ')
            break
        else:
            print('\nThere was something wrong with your entry. Please try again...\n')
    return username, password


# Retrieves the user's api key
def getkey(fwip):
    while True:
        try:
            username, password = getCreds()
            keycall = f'https://{fwip}/api/?type=keygen&user={username}&password={password}'
            r = requests.get(keycall, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') == 'success':
                apikey = tree.find('./result/key').text
                break
            else:
                print('\nYou have entered an incorrect username or password. Please try again...\n')
        except requests.exceptions.ConnectionError:
            print('\nThere was a problem connecting to the firewall. Please check the address and try again...\n')
            exit()
    return apikey


# Determine whether the device is Panorama or firewall
def getDevType(fwip, mainkey, devTree):
    if devTree is None:
        devURL = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/device-group&key={mainkey}"
        r = requests.get(devURL, verify=False)
        devTree = ET.fromstring(r.text)
    if devTree.find('.//device-group/entry') is None:
        devType = 'fw'
        print('\n\n...Auto-detected device type to be a firewall...\n')
    else:
        devType = 'pano'
        print('\n\n...Auto-detected device type to be Panorama...\n')
    time.sleep(1)
    return devType


# Presents the user with a choice of device-groups
def getDG(fwip, mainkey, devTree):
    if devTree is None:
        dgXmlUrl = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/device-group&key={mainkey}"
        r = requests.get(dgXmlUrl, verify=False)
        devTree = ET.fromstring(r.text)
        devTreeString = './/device-group/entry'
    else:
        devTreeString = 'devices/entry/device-group/entry'
    dgList = []
    for entry in devTree.findall(devTreeString):
        dgList.append(entry.get('name'))
    while True:
        try:
            print("\n\nHere's a list of device groups found in Panorama...\n")
            i = 1
            for dgName in dgList:
                print(f'{i}) {dgName}')
                i += 1
            dgChoice = int(input('\nChoose a number for the device-group:\n\nAnswer: '))
            reportDG = dgList[dgChoice - 1]
            break
        except:
            print("\n\nThat's not a number in the list, try again...\n")
            time.sleep(1)
    return reportDG


# Presents the user with a choice of rulebases
def getRulebaseCategory():
    while True:
        try:
            answerDict = {1: 'security', 2: 'nat', 3: 'decryption', 4: 'authentication'}
            rbType = int(input('\n\nChoose the type of rulebase you would like to search...\n\n1) Security\n2) NAT\n3) Decryption\n4) Authentication\n\nAnswer: '))
            if answerDict.get(rbType) is not None:
                return answerDict.get(rbType)
        except:
            pass
        print("\n\nThat's not a number in the list, try again...\n")
        time.sleep(1)


# Presents the user with a choice of pre or post rulebase, if dev type is Panorama
def pre_or_post():
    while True:
        try:
            answerDict = {1: 'pre-rulebase', 2: 'post-rulebase'}
            rbType = int(input('\n\nWould you like to search Pre or Post-rulebase?\n\n1) Pre-Rulebase\n2) Post-Rulebase\n\nAnswer: '))
            if answerDict.get(rbType) is not None:
                return answerDict.get(rbType)
        except:
            pass
        print("\n\nThat's not a number in the list, try again...\n")
        time.sleep(1)


# Retrieves the policies from the rulebase
def getPolicies(fwip, mainkey, dg, devTree, rulebase_type, rulebase_category):
    if devTree is None:
        if dg is None:
            xmlUrl = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/vsys/entry/rulebase/{rulebase_category}/rules&key={mainkey}"
        else:
            xmlUrl = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/device-group/entry[@name='{dg}']/{rulebase_type}/{rulebase_category}/rules&key={mainkey}"
        r = requests.get(xmlUrl, verify=False)
        devTree = ET.fromstring(r.text)
        devTreeString = './/rules/entry'
    else:
        if dg is None:
            devTreeString = f'.//rulebase/{rulebase_category}/rules/entry'
        else:
            devTreeString = f".//device-group/entry[@name='{dg}']/{rulebase_type}/{rulebase_category}/rules/entry"
    return devTree.findall(devTreeString)


# Filter policies based on user-provided regex string
def filterPolicies(policyTree, regexString, new_zone):
    policyMatches = {}
    allMatches = []
    for entry in policyTree:
        toMatches = []
        fromMatches = []
        for to_member in entry.findall('./to/member'):
            if re.match(regexString, to_member.text) and to_member.text != new_zone:
                toMatches.append(to_member.text)
        for from_member in entry.findall('./from/member'):
            if re.match(regexString, from_member.text) and from_member.text != new_zone:
                fromMatches.append(from_member.text)
        if toMatches or fromMatches:
            policyMatches[entry.get('name')] = {'to': toMatches, 'from': fromMatches}
        allMatches.extend(set(toMatches + fromMatches))
    if not policyMatches:
        return policyMatches
    print('\n\nThe following zones matched your search query:')
    print(', '.join(set(allMatches)))
    time.sleep(1)
    while True:
        user_input = input(f'\n\nThere are {len(policyMatches)} matching policies. Would you like to see the policies? [Y/n]  ')
        if user_input.lower() == 'y' or user_input == '':
            displayMatches(policyMatches)
            return policyMatches
        elif user_input.lower() == 'n':
            return policyMatches
        else:
            print("\nWrong entry, try a 'y' or 'n' this time...")
            time.sleep(1)


# Display policies with zone/regex string matches
def displayMatches(policyMatches):
    time.sleep(1)
    for policy_name, policy_value in policyMatches.items():
        print('\nMatching policy: ' + policy_name)
        for key, value in policy_value.items():
            if value:
                print(f"{key} zone match: {', '.join(value)}")


# Build a dictionary of zones to removea, and a list of element strings to add, it also checks the lenth
# of the requests API call to make sure it doesn't go over the 6K character limit, splitting if needed
def elementBuilder(policyMatches, new_zone, apiCall_piece):
    elements_list = []
    members_to_delete = {}
    elements_all = ''
    for policy_name, policy_dict in policyMatches.items():
        members = []
        to_element = f"<entry name='{policy_name}'><to><member>{new_zone}</member></to></entry>"
        from_element = f"<entry name='{policy_name}'><from><member>{new_zone}</member></from></entry>"
        if len(elements_all) + len(apiCall_piece) + len(to_element) > 5000:
            elements_list.append(elements_all)
            elements_all = ''
        if policy_dict['to']:
            elements_all += to_element
            for item in policy_dict['to']:
                members.append(f"/entry[@name='{policy_name}']/to/member[text()='{item}']")
                members_to_delete[policy_name] = members
        if len(elements_all) + len(apiCall_piece) + len(from_element) > 5000:
            elements_list.append(elements_all)
            elements_all = ''
        if policy_dict['from']:
            elements_all += from_element
            for item in policy_dict['from']:
                members.append(f"/entry[@name='{policy_name}']/from/member[text()='{item}']")
                members_to_delete[policy_name] = members
    if elements_all != '':
        elements_list.append(elements_all)
    return elements_list, members_to_delete


# Push policy changes via API
def apiPush(fwip, mainkey, dg, rulebase_type, rulebase_category, policyMatches, new_zone):
    if dg is None:
        baseUrl = f"https://{fwip}/api/?type=config&action=set&xpath=/config/devices/entry/vsys/entry/rulebase/{rulebase_category}/rules"
        xmlUrl = baseUrl + "&element=&key=" + mainkey
    else:
        baseUrl = f"https://{fwip}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name='{dg}']/{rulebase_type}/{rulebase_category}/rules"
        xmlUrl = baseUrl + "&element=&key=" + mainkey
    zone_add_list, members_to_delete = elementBuilder(policyMatches, new_zone, xmlUrl)
    input('\n\nHit Enter to push the new zone to the policies that matched (or CTRL+C to exit the script)... ')
    time.sleep(1)
    print('\nPolicy changes being pushed, please be patient...')
    for zone_element in zone_add_list:
        fullUrl = baseUrl + "&element=" + zone_element + "&key=" + mainkey
        r = requests.get(fullUrl, verify=False)
        tree = ET.fromstring(r.text)
        if tree.get('status') != "success":
            print(f'\n\nThere was an issue with an API call, below is the faulty call...\n\n{fullUrl}\n')
            exit()
    print('\n\n...Done...')
    time.sleep(1)
    input(f'\n\nThere are {sum([len(members_to_delete[i]) for i in members_to_delete])} zones that need to be removed from the {len(members_to_delete)} matching policies. Each zone is removed by a separate API call\nPlease be aware that this could have an impact on the management plane of your PAN device\n\nHit Enter to push the API calls to remove the old zones from the policies that matched (or CTRL+C to exit the script)... ')
    print('\n')
    for key, value in members_to_delete.items():
        for item in value:
            fullUrl = baseUrl.replace('&action=set', '&action=delete') + item + "&key=" + mainkey
            r = requests.get(fullUrl, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') != "success":
                print(f'\n\nThere was an issue with the API call for {key}, below is the faulty call...\n\n{fullUrl}\n')
                input('\n\nHit Enter to continue removing zones (or CTRL+C to exit the script)... ')
            else:
                print(f'Policy Name: {key} - Old zone successfully removed')


# Push changes to the config, if offline mode is used
def configUpdate(devTree, dg, rulebase_type, rulebase_category, policyMatches, new_zone):
    if dg is None:
        devTreeString = f'.//rulebase/{rulebase_category}/rules/entry'
    else:
        devTreeString = f".//device-group/entry[@name='{dg}']/{rulebase_type}/{rulebase_category}/rules/entry"
    input('\n\nHit Enter to push the zone changes to PAN config (or CTRL+C to exit the script)... ')
    for policy_name, zone_elements in policyMatches.items():
        for key, value in zone_elements.items():
            if value:
                tree_textToReplace = devTree.find(f"{devTreeString}[@name='{policy_name}']/{key}/member[.='{value[0]}']")
                count = 0
                for item in value:
                    if count == 0:
                        tree_textToReplace.text = new_zone
                    else:
                        tree_textToRemove = devTree.find(f"{devTreeString}[@name='{policy_name}']/{key}/member[.='{item}']")
                        parent = devTree.find(f"{devTreeString}[@name='{policy_name}']/{key}")
                        parent.remove(tree_textToRemove)
                    count += 1


def main():
    fwip = None
    mainkey = None
    devTree = None
    path = ''

    # Call functions to prompt user for device address and retrieve the API key, or load config from arg if added by user
    if len(sys.argv) < 2:
        fwip = getfwipfqdn()
        mainkey = getkey(fwip)
    else:
        file = sys.argv[1]
        panConfig = ET.parse(file)
        if '/' or '\\' in file:
            path, file = os.path.split(file)
        devTree = panConfig.getroot()
        print('\n\n...Device config loaded from command argument...')
        time.sleep(1)

    # Determine whether the device is Panorama or firewall
    devType = getDevType(fwip, mainkey, devTree)

    while True:
        # If Panorama is the device type, prompt user to choose device group
        panoDG = None
        if devType == 'pano':
            panoDG = getDG(fwip, mainkey, devTree)

        # Prompt the user to choose a rulebase category
        rulebase_category = getRulebaseCategory()

        # If Panorama is the device type, prompt user to choose pre or post-rulebase
        rulebase_type = None
        if panoDG is not None:
            rulebase_type = pre_or_post()

        # Retrieve the policy rules
        policyTree = getPolicies(fwip, mainkey, panoDG, devTree, rulebase_type, rulebase_category)
        if not policyTree:
            time.sleep(1)
            print('\n\nThere were no policies in the rulebase chosen, try again...')
            continue

        # Prompt user to enter regex string and name of new zone, then filter the policies based on the string
        while True:
            regexString = input('\n\nEnter your regex string for search and replace: ')
            new_zone = input('\nEnter the new zone (The zone must exist on the firewall before pushing this change): ')
            if re.match(regexString, new_zone):
                time.sleep(1)
                input("\n\nNote: Your regex string matches your new zone name. If there are any policies that currently contain your new zone,\ndon't worry, they'll be removed from the search query, so they won't be removed from policy. Hit Enter to continue... ")
            policyMatches = filterPolicies(policyTree, regexString, new_zone)
            if not policyMatches:
                time.sleep(1)
                print('\n\nThere were no policies with zones matching your regex string. Try a new string...')
            else:
                break

        # Push changes through API, or directly to config if offline mode
        if devTree is None:
            apiPush(fwip, mainkey, panoDG, rulebase_type, rulebase_category, policyMatches, new_zone)
            print(f'\n\n\nCongrats, all zones have been replaced in the {rulebase_category} rulebase!')
        else:
            configUpdate(devTree, panoDG, rulebase_type, rulebase_category, policyMatches, new_zone)
            print(f'\n\n\nCongrats, all zones have been replaced in the {rulebase_category} rulebase!')
            time.sleep(1)
            print('\n\nWriting config to file. Please hold....\n')
            panConfig.write(os.path.join(path, 'EDITED_BY_SCRIPT_' + file))
            print('\n\nYour changes were successfully written to config')
            print('\nThe config was saved as EDITED_BY_SCRIPT_' + file)
            time.sleep(1)
            print('\n\n\nHave a great day!!\n\n')
            exit()

        # Allow user to run the script again
        while True:
            user_input = input('\n\nWould you like to run this script again for the same PAN device? [Y/n]  ')
            if user_input.lower() == 'y' or user_input == '':
                break
            elif user_input.lower() == 'n':
                print('\n\n\nHave a great day!!\n\n')
                time.sleep(1)
                exit()
            else:
                print("\nWrong entry, try a 'y' or 'n' this time...")
                time.sleep(1)


if __name__ == '__main__':
    main()
