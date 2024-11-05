from netmiko import ConnectHandler
from log import authLog

import traceback
import threading
import re
import os

interface = ''
snoopTrust = "ip dhcp snooping trust"

shHostname = "show run | i hostname"
shIntStatus = "show interface status | exc SDW|sdw|LUM|lum|Lum|Ap|core|Po|Core|CORE|core|trunk"
shIntTrunk = "show interface trunk | exclude Vlans|1500|Ap"
shIntCore = "show interface description | inc Core|CORE|core"

snoopGenIntConfigOutList = []

snoopGlobalConfig = [
    'ip dhcp snooping vlan 2-3999',
    'no ip dhcp snooping information option',
    'ip dhcp snooping',
    'errdisable recovery cause dhcp-rate-limit',
    'errdisable recovery interval 300',
    'class-map match-any system-cpp-police-protocol-snooping',
    'description Protocol snooping',
    'class-map match-any system-cpp-police-dhcp-snooping',
    'description DHCP snooping'
]

snoopIntConfig = [
    f'int {interface}',
    'ip dhcp snooping trust'
]

snoopGenIntConfig = [
    f'int {interface}',
    'ip dhcp snooping limit rate 50'
]

catchAll = [
    'event manager applet catchall',
    'event cli pattern ".*" sync no skip no',
    'action 1 syslog msg "$_cli_msg"'
]

delCatchAll = [
    'no event manager applet catchall'
]

# Regex Patterns
intPatt = r'[a-zA-Z]+\d+\/(?:\d+\/)*\d+'
intPattPo = r'\b(?:[a-zA-Z]+\d+\/(?:\d+\/)*\d+|Po\d+)\b'
intPatt2 = r'[Te]+\d+\/(?:1+\/)+\d+'

def dhcpSnooopTr(validIPs, username, netDevice):
    # This function is to take a show run

    validIPs = [validIPs]
    for validDeviceIP in validIPs:
        descripIntList = []
        TrunkIntList = []
        snoopIntConfigOut = ""
        snoopIntConfigOut1 = ""

        try:
            validDeviceIP = validDeviceIP.strip()
            currentNetDevice = {
                'device_type': 'cisco_xe',
                'ip': validDeviceIP,
                'username': username,
                'password': netDevice['password'],
                'secret': netDevice['secret'],
                'global_delay_factor': 2.0,
                'timeout': 120,
                'session_log': 'netmikoLog.txt',
                'verbose': True,
                'session_log_file_mode': 'append'
            }

            print(f"Connecting to device {validDeviceIP}...")
            with ConnectHandler(**currentNetDevice) as sshAccess:
                try:
                    sshAccess.enable()
                    catchAllOut = sshAccess.send_config_set(catchAll)
                    authLog.info(f"The script catchall was sent to the device {validDeviceIP}")
                    print(f"INFO: Script catchall was configured on the device {validDeviceIP}")
                    shHostnameOut = sshAccess.send_command(shHostname)
                    authLog.info(f"User {username} successfully found the hostname {shHostnameOut}")
                    shHostnameOut = shHostnameOut.replace('hostname', '')
                    shHostnameOut = shHostnameOut.strip()
                    shHostnameOut = shHostnameOut + "#"

                    snoopGlobalConfigOut = sshAccess.send_config_set(snoopGlobalConfig)
                    authLog.info(f"Automation sent the following General Configuration to device {validDeviceIP}\n{snoopGlobalConfigOut}")
                    print(f"INFO: The following General Configuration was sent to the device {validDeviceIP}\n{snoopGlobalConfigOut}")

                    shIntStatusOut = sshAccess.send_command(shIntStatus)
                    authLog.info(f"Automation ran the command \"{shIntStatus}\" on device {validDeviceIP}\n{shHostnameOut}{shIntStatusOut}")
                    print(f"INFO: Running the following command: \"{shIntStatus}\" on device {validDeviceIP}\n{shHostnameOut}{shIntStatusOut}")
                    shIntStatusOut1 = re.findall(intPatt, shIntStatusOut)
                    authLog.info(f"Automation found the following interfaces on device {validDeviceIP}: {shIntStatusOut1}")
                    # shIntStatusOut2 = [match for match in shIntStatusOut1 if not re.match(intPatt2, match)]
                    # authLog.info(f"Automation filtered the following interfaces on device {validDeviceIP}: {shIntStatusOut2}")
                    # print(f"INFO: The following interfaces will be modified: {shIntStatusOut2}")

                    for interface in shIntStatusOut1:
                        print(f"INFO: Configuring interface {interface} on device {validDeviceIP}")
                        snoopGenIntConfig[0] = f'int {interface}'
                        snoopGenIntConfigOut = sshAccess.send_config_set(snoopGenIntConfig)
                        authLog.info(f"Automation sent the following configuration to interface {interface} on device {validDeviceIP}\n{snoopGenIntConfigOut}")
                        print(f"INFO: Successfully configured Interface {interface} on device {validDeviceIP}\n")
                        snoopGenIntConfigOutList.append(snoopGenIntConfigOut)

                    snoopGenIntConfigOutStr = " ".join(snoopGenIntConfigOutList)
                    snoopGenIntConfigOutStr.split("\n")

                    print(f"INFO: Taking a \"{shIntTrunk}\" for device: {validDeviceIP}")
                    shIntTrunkOut = sshAccess.send_command(shIntTrunk)
                    authLog.info(f"Automation successfully ran the command:{shIntTrunk}\n{shHostnameOut}{shIntTrunk}\n{shIntTrunkOut}")

                    shIntTrunkOut1 = re.findall(intPattPo, shIntTrunkOut)
                    authLog.info(f"The following interfaces were found under the command: {shIntTrunk}: {shIntTrunkOut1}")

                    if not shIntTrunkOut1 == []:
                        
                        for interface in shIntTrunkOut1:
                            interface = interface.strip()
                            print(f"INFO: Checking configuration for interface {interface} on device {validDeviceIP}")
                            authLog.info(f"Checking configuration for interface {interface} on device {validDeviceIP}")
                            interfaceOut = sshAccess.send_command(f'show run int {interface}')
                            if snoopTrust in interfaceOut:
                                print(f"INFO: Interface {interface} has configured {snoopTrust} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} has configured {snoopTrust} on device {validDeviceIP}")
                                TrunkIntList.append(f"Interface {interface} has configured {snoopTrust}")
                                snoopIntConfigOut = f"No interfaces were modified, \"{snoopTrust}\" is already configured on interface {interface}"
                                authLog.info(f"No interfaces were modified on device {validDeviceIP}, \"{snoopTrust}\" is already configured on interface {interface}")
                            else:
                                print(f"INFO: Interface {interface} does NOT have configured {snoopTrust} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} does NOT have configured {snoopTrust} on device {validDeviceIP}")
                                TrunkIntList.append(f"Interface {interface} does NOT have configured {snoopTrust} on device {validDeviceIP}")
                                print(f"INFO: Configuring interface {interface} on device {validDeviceIP}")
                                snoopIntConfig[0] = f'int {interface}'
                                snoopIntConfigOut = sshAccess.send_config_set(snoopIntConfig)
                                authLog.info(f"Automation sent the following configuration to interface {interface} on device {validDeviceIP}\n{snoopIntConfigOut}")
                                print(f"INFO: Successfully configured interface {interface} on device {validDeviceIP} with the below configuration:\n{snoopIntConfigOut}")
                    else:
                        print(f"INFO: No interfaces found under {shIntTrunk}")
                        authLog.info(f"No interfaces found under {shIntTrunk}")

                    print(f"INFO: Taking a \"{shIntCore}\" for device: {validDeviceIP}")
                    shIntCoreOut = sshAccess.send_command(shIntCore)
                    authLog.info(f"Automation successfully ran the command:{shIntCore}\n{shHostnameOut}{shIntCore}\n{shIntCoreOut}")

                    shIntCoreOut1 = re.findall(intPatt, shIntCoreOut)
                    authLog.info(f"The following interfaces were found under the command: {shIntCore}: {shIntCoreOut1}")

                    if not shIntCoreOut1 == []:

                        for interface in shIntCoreOut1:
                            interface = interface.strip()
                            print(f"INFO: Checking configuration for interface {interface} on device {validDeviceIP}")
                            authLog.info(f"Checking configuration for interface {interface} on device {validDeviceIP}")
                            interfaceOut = sshAccess.send_command(f'show run int {interface}')
                            if snoopTrust in interfaceOut:
                                print(f"INFO: Interface {interface} has configured {snoopTrust} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} has configured {snoopTrust} on device {validDeviceIP}")
                                descripIntList.append(f"Interface {interface} has configured {snoopTrust}")
                                snoopIntConfigOut1 = f"No interfaces were modified, \"{snoopTrust}\" is already configured on interface {interface}"
                                authLog.info(f"No interfaces were modified on device {validDeviceIP}, \"{snoopTrust}\" is already configured on interface {interface}")
                            else:
                                print(f"INFO: Interface {interface} does NOT have configured {snoopTrust} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} does NOT have configured {snoopTrust} on device {validDeviceIP}")
                                descripIntList.append(f"Interface {interface} does NOT have configured {snoopTrust} on device {validDeviceIP}")
                                print(f"INFO: Configuring interface {interface} on device {validDeviceIP}")
                                snoopIntConfig[0] = f'int {interface}'
                                snoopIntConfigOut1 = sshAccess.send_config_set(snoopIntConfig)
                                print(f"INFO: Successfully configured interface {interface} on device {validDeviceIP} with the below configuration:\n{snoopIntConfigOut1}")
                                authLog.info(f"Automation sent the following configuration to interface {interface} on device {validDeviceIP}\n{snoopIntConfigOut1}")
                    else:
                        print(f"INFO: No interfaces found under {shIntCore}")
                        authLog.info(f"No interfaces found under {shIntCore}")

                    delCatchAllOut = sshAccess.send_config_set(delCatchAll)
                    authLog.info(f"The script catchall was unconfigured from the device {validDeviceIP}")
                    print(f"INFO: Script catchall was unconfigured from the device {validDeviceIP}")

                    print(f"INFO: Running configuration saved for device {validDeviceIP}")
                    writeMemOut = sshAccess.send_command('write')
                    print(f"INFO: All the configuration has been applied")
                    authLog.info(f"Running configuration saved for device {validDeviceIP}\n{shHostnameOut}'write'\n{writeMemOut}")

                    with open(f"Outputs/{validDeviceIP} DHCP Snooping Config.txt", "a") as file:
                        file.write(f"User {username} connected to device IP {validDeviceIP}\n\n")
                        file.write(f"Interfaces under {shIntTrunk}:\n{TrunkIntList}\n")
                        file.write(f"Interfaces under {shIntCore}:\n{descripIntList}\n")
                        file.write(f"\nConfiguration applied to the ports:\n")
                        file.write(f"\n{snoopIntConfigOut}\n")
                        file.write(f"\n{snoopIntConfigOut1}\n")
                        file.write(f"\nGeneral configuration applied to the device:\n{snoopGlobalConfigOut}\n")
                        file.write(f"\nConfiguration applied to every port:{snoopGenIntConfigOutStr}")
                        authLog.info(f"File {validDeviceIP}_dhcpSnoopCheck.txt was created successfully.")

                    print(f"Outputs and files successfully created for device {validDeviceIP}.\n")
                    print("For any erros or logs please check Logs -> authLog.txt\n")
                    print(f"Program finished, all the configuration has been applied.")

                except Exception as error:
                    print(f"ERROR: An error occurred: {error}\n", traceback.format_exc())
                    authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error} \n {traceback.format_exc()}")
                    #authLog.error(traceback.format_exc())
                    os.system("PAUSE")
       
        except Exception as error:
            print(f"ERROR: An error occurred: {error}\n", traceback.format_exc())
            authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error}\n",traceback.format_exc())
            authLog.error(traceback.format_exc())
            with open(f"failedDevices.txt","a") as failedDevices:
                failedDevices.write(f"User {username} connected to {validDeviceIP} got an error.\n")

def dot1xThread(validIPs, username, netDevice):
    threads = []

    for validDeviceIP in validIPs:
        thread = threading.Thread(target=dhcpSnooopTr, args=(validDeviceIP, username, netDevice))
        thread.start()
        authLog.info(f"Thread {thread} started.")
        threads.append(thread)
        authLog.info(f"Thread {thread} appended to threads: {threads}")

    for thread in threads:
        thread.join()