#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import requests
import argparse
import netmiko
from netmiko.ssh_autodetect import SSHDetect
from netmiko.ssh_dispatcher import ConnectHandler
from netmiko import ConnectHandler
try:
    import protobix3 as protobix
except:
    import protobix

PBX_SRV = '127.0.0.1'
PBX_PORT = 10051

KEY_TTL = 14400
REDIS = {
    "ip": "192.168.37.218",
    "port": "7379",
    "db": "6",
    "prefix": "Template_Net_Syslog"
}
DEVICES = {
    "cisco_nxos": {
        "command": "show bfd neighbors vrf all",
        "firstWord": "OurAddr",
        "neighbor": "1",
        "id": "2",
        "state": "5",
        "Up": 1,
        "sessionBad": ".*BFD.*SESSION_STATE_DOWN.*session.*",
        "sessionOk": ".*BFD.*SESSION_STATE_UP.*session.*"

    },
    "cisco_ios": {
        "command": "show bfd neighbors",
        "firstWord": "NeighAddr",
        "neighbor": "0",
        "id": "1",
        "state": "3",
        "Up": 1,
        "sessionBad": ".*BFD_SESS_DESTROYED.*ld:",
        "sessionOk": ".*BFD_SESS_UP.*ld:"
    }
}

def send_data(sendData, dataType):
    zbx_datacontainer = protobix.DataContainer()
    zbx_datacontainer.server_active = PBX_SRV
    zbx_datacontainer.server_port = int(PBX_PORT)
    zbx_datacontainer.data_type = dataType
    zbx_datacontainer.add(sendData)
    zbx_datacontainer.send()

def ios_data(device, args):
    resultDict = {}
    device.send_command('terminal length 0')
    bfdpeers = device.send_command('show bfd neighbors | i 10.|172.16.|192.168.|Addr|Gi|Po|Tul|Fa')
    allInterfacesDescription = device.send_command("show interfaces description").split('\n')
    decriptionPosition = allInterfacesDescription[0].find("Description")
    splited = bfdpeers.split('\n')
    dictKeys = splited.pop(0).split()
    peersList = []
    for i in splited:
        if i:
            peersList.append(dict(zip(dictKeys, i.split())))
    for interface in peersList:
        interfaceDescription = ''
        interfaceName = interface.get("Int")
        for line in allInterfacesDescription:
            if line.startswith(interfaceName):
                interfaceDescription = line[decriptionPosition:].strip()
                break
        resultDict["name[{}]".format(interface.get("NeighAddr"))] = interfaceName
        resultDict["description[{}]".format(interface.get("NeighAddr"))] = interfaceDescription
    dataToSend = {
        args.host :
            resultDict
    }
    send_data(dataToSend, 'items')

def nexus_data(device, args):
    resultDict = {}
    bfdpeers = device.send_command("show bfd neighbors vrf all | i 10.|172.16.|192.168.|Addr|Gi|Po|Tul|Fa")
    splited = bfdpeers.split('\n')
    dictKeys = splited.pop(0).split()
    peersList = []
    for i in splited:
        if i:
            peersList.append(dict(zip(dictKeys, i.split())))
    for interface in peersList:
        interfaceName = interface.get("Int")
        interfaceDescription = device.send_command("show interface {} description".format(interfaceName)).split('\n')
        if interfaceDescription[1].startswith("Interface"):
            decriptionPosition = interfaceDescription[1].find("Description")
            interfaceDescription = interfaceDescription[3][decriptionPosition:].strip()
        elif interfaceDescription[2].startswith("Port"):
            decriptionPosition = interfaceDescription[2].find("Description")
            interfaceDescription = interfaceDescription[4][decriptionPosition:].strip()
        resultDict["name[{}]".format(interface.get("NeighAddr"))] = interfaceName
        resultDict["description[{}]".format(interface.get("NeighAddr"))] = interfaceDescription
    dataToSend = {
        args.host :
            resultDict
    }
    send_data(dataToSend, 'items')

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", help="Network device ip address.", required=True)
    parser.add_argument("--user", help="Network device login.", required=True)
    parser.add_argument("--password", help="Network device password", required=True)
    parser.add_argument("--host", help="Zabbix host for trapper data.", required=True)
    return parser.parse_args()

def determine_type(args):
    remote_device = {
        "device_type": "autodetect",
        "host": args.ip,
        "username": args.user,
        "password": args.password
    }
    guesser = SSHDetect(**remote_device)
    bestMatch = guesser.autodetect()
    return bestMatch

def get_device_type(args, errors):
    erCode = 0
    deviceType = None
    getUrl = "http://{0}:{1}/{2}/GET/{3}_{4}".format(
        REDIS["ip"],
        REDIS["port"],
        REDIS["db"],
        REDIS["prefix"],
        args.ip
    )
    try:
        redisResult = json.loads(requests.get(getUrl).text).get("GET")
        if not redisResult:
            try:
                deviceType = determine_type(args)
            except Exception as e:
                if isinstance(e, netmiko.ssh_exception.NetMikoTimeoutException) or (args.host.upper().startswith("UAK") and str(e).startswith("Unable to find prompt")):
                    erCode = 1
                elif isinstance(e, netmiko.ssh_exception.NetMikoAuthenticationException) or isinstance(e, netmiko.ssh_exception.AuthenticationException):
                    erCode = 2
                else:
                    errors.append(str(e))
            if deviceType:
                setUrl = "http://{0}:{1}/{2}/SETEX/{3}_{4}/{5}/{6}".format(
                    REDIS["ip"],
                    REDIS["port"],
                    REDIS["db"],
                    REDIS["prefix"],
                    args.ip,
                    KEY_TTL,
                    deviceType
                )
                requests.get(setUrl)
        else:
            deviceType = redisResult
    except:
        errors.append("Сервер REDIS недоступен.")
        pass
    return deviceType, erCode

def form_lld_data(args, deviceType, errors):
    erCode = 0
    lldData = []
    stateData = {}
    found = False
    startFrom = 1
    try:
        device = ConnectHandler(device_type=deviceType, ip=args.ip, username=args.user, password=args.password)
        bfdNeighReturn = device.send_command(DEVICES[deviceType].get("command"))
        bfdSplitted = bfdNeighReturn.split('\n')
        for i in range(len(bfdSplitted)):
            if bfdSplitted[i].startswith(DEVICES[deviceType].get("firstWord")):
                startFrom += i
                found = True
                break
        if found:
            for line in bfdSplitted[startFrom:]:
                if line:
                    splittedLine = line.split()
                    neighbor = splittedLine[int(DEVICES[deviceType].get("neighbor"))]
                    sessId = splittedLine[int(DEVICES[deviceType].get("id"))].split('/')[0]
                    sessionState = splittedLine[int(DEVICES[deviceType].get("state"))]
                    stateData["state[{0}]".format(neighbor)] = DEVICES[deviceType].get(sessionState, 0)
                    lldData.append(
                        {
                            "{#BFD.SESSION.ID}" : sessId,
                            "{#BFD.SESSION.IP}" : neighbor,
                            "{#BFD.SESSION.OK}" : DEVICES[deviceType].get("sessionOk"),
                            "{#BFD.SESSION.BAD}": DEVICES[deviceType].get("sessionBad")
                        }
                    )
            if deviceType == "cisco_nxos":
                nexus_data(device, args)
            elif deviceType == "cisco_ios":
                ios_data(device, args)

    except Exception as e:
        if isinstance(e, netmiko.ssh_exception.NetMikoTimeoutException) or (args.host.upper().startswith("UAK") and str(e).startswith("Unable to find prompt")):
            erCode = 1
        elif isinstance(e, netmiko.ssh_exception.NetMikoAuthenticationException) or isinstance(e, netmiko.ssh_exception.AuthenticationException):
            erCode = 2
        else:
            errors.append(str(e))
        pass #return empty lld
    return lldData, stateData, erCode

def main():
    erCode = 0
    errorTimeOut = 0
    errorAuth = 0
    state = {}
    errors = []
    args = parse_args()
    deviceType, erCode = get_device_type(args, errors)
    if not deviceType in DEVICES:
        lldData = []
    else:
        lldData, state, erCode = form_lld_data(args, deviceType, errors)
    lldSendData = {
        args.host: {
            "bfd.session.lld" : lldData
            }
        }
    send_data(lldSendData, "lld")
    if erCode == 1:
        errorTimeOut = 1
    elif erCode == 2:
        errorAuth = 1
    state.update(
        {
            "bfd.script.error": '\n'.join(errors),
            "bfd.timeout.error": errorTimeOut,
            "bfd.auth.error": errorAuth
        }
    )
    stateData = {
        args.host : state
       }
    send_data(stateData, "items")
    print(0)

if __name__ == "__main__":
    main()
