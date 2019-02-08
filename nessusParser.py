import sys
import os
import untangle
import json
import os.path
import textwrap
import msvcrt
import datetime

lineBreak = "+--------------------------------------------------------------------------------+"
scanDate = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
# creates an XML file from the Nessus file to use an XML parser
def makeXMLFromNessus(file):
    fileName = file[:len(file) - 7]
    if os.path.exists("./" + fileName + ".xml"):
        print("File already exists, using " + fileName +".xml")
        return fileName + ".xml"
    else:
        print("Creating " + fileName +".xml")
        with open(file, 'r') as nessusFile, open(fileName + ".xml", 'w') as xmlFile:
            xmlFile.write('<?xml version="1.0" ?>\n<root>\n')
            nessusFile.readline()
            while True:
                x = nessusFile.readline()
                if x:
                    xmlFile.write(x)
                else:
                    break
            xmlFile.write("\n</root>")
        return fileName + ".xml"

# extract the hosts from the XML file
def getReportHosts(report):
    parsed = untangle.parse(report)
    return parsed.root.NessusClientData_v2.Report.ReportHost

# get the action items from each host
def getReportItems(host):
    return host.ReportItem

# return the desired fields from each item
def getFields(items, data):
    for item in items:
        if untangle.Element.get_elements(item, name="risk_factor")[0].cdata in data['risk']:
            prettyPrint(item, data)

# untangle.Element.get_elements(item, name="fname")
def prettyPrint(item, data):
    print(lineBreak)
    thingsToPrint = data['fields']
    for thing in thingsToPrint:
        try:
            element = untangle.Element.get_elements(item, name=thing)
            text = "- " + str(thing) + ": " + str(element[0].cdata)
        except:
            element = item[thing]
            text = "- " + str(thing) + ": " + str(element)
        print(textwrap.fill(text, 80))
    
    # ask what to do with em
    response = getResponse(data)
    # take action afterwards
    handleResponse(response, item, data)
    return

# promts the user for what to do with the given item
def getResponse(data):
    print(lineBreak)
    index = 1
    for option in data['options']:
        print(str(index) + ": " + option)
        index = index + 1
    while True:
        output = msvcrt.getch()
        option = int.from_bytes(output, byteorder=sys.byteorder) - 49
        if option >= 0 and option < len(data['options']):
            action = data['options'][option]
            break
        elif option == -22:
            sys.exit(0)
        else:
            print("Invalid selection. Choose from shown options.")
    
    return action

# do something yet to be determined with the response
def handleResponse(response, item, data):
    f = open(scanDate + "/" + response + ".txt", "a")
    f.write("\n" + lineBreak + "\n")
    thingsToPrint = data['fields']
    for thing in thingsToPrint:
        element = untangle.Element.get_elements(item, name=thing)
        try:
            text = "- " + str(thing) + ": " + str(element[0].cdata)
        except:
            text = "- " + str(thing) + ": " + str(element)
        f.write(textwrap.fill(text, 80) + "\n")
    f.close()
    return

# run the script
def main():
    global scanDate
    config = []
    # make sure a file was specified
    if len(sys.argv) < 2:
        print("No file specified. Exiting...")
        exit
    else:
        if len(sys.argv) == 2:
            print("No config specified, using default")
            config = "default"
        else:
            config = sys.argv[2]
        with open('config.json') as f:
            data = json.load(f)[config]
    scanDate = "ParsedScans/" + scanDate + "_" + config
    os.mkdir(str(scanDate))
    # make the nessus file into an xml file (add root tags)
    xmlFile = makeXMLFromNessus(sys.argv[1])
    # parse the new xml file
    reportHosts = getReportHosts(xmlFile)
    # print(len(reportHosts))
    # extract each ReportHost
    i = 0
    # this is wrong, gets the string instead of the jawn
    for host in reportHosts:
        # extract ReportItems
        items = getReportItems(host)
        print(lineBreak)
        print("Host " + str(i) + ": " + host['name'])
        for option in data['options']:
            f = open(scanDate + "/" + option + ".txt", "a")
            f.write("\n" + lineBreak + "\nHost " + str(i) + ": " + host['name'] + "\n" + lineBreak + "\n")
        print(lineBreak)
        # filter appropriate fields
        displayFields = getFields(items, data)
        # print em
        # print("ITEM " + str(i) + ":\n" + json.dumps(displayFields, indent=2))
        i = i + 1
        print()

main()