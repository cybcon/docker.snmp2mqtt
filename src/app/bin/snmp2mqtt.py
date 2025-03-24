# -*- coding: utf-8 -*-
""" ***************************************************************************
snmp2mqtt.py - Read device information via SNMP and publish them in a MQTT
  topic as json formatted string.
Author: Michael Oberdorf
Date: 2021-08-14
Last modified by: Michael Oberdorf
Last modified at: 2025-03-24
*************************************************************************** """
import asyncio
import datetime
import json
import logging
import os
import ssl
import sys

import paho.mqtt.client as mqtt
import pysnmp
from pysnmp.hlapi.v3arch.asyncio import (
    USM_AUTH_HMAC96_MD5,
    USM_AUTH_HMAC96_SHA,
    USM_AUTH_HMAC128_SHA224,
    USM_AUTH_HMAC192_SHA256,
    USM_AUTH_HMAC256_SHA384,
    USM_AUTH_HMAC384_SHA512,
    USM_PRIV_CBC56_DES,
    USM_PRIV_CBC168_3DES,
    USM_PRIV_CFB128_AES,
    USM_PRIV_CFB192_AES,
    USM_PRIV_CFB256_AES,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
)

VERSION = "1.1.0"

script_path = os.path.dirname(__file__)
base_path = os.path.dirname(script_path)
config_file = base_path + "/etc/snmp2mqtt.json"
if "CONFIG_FILE" in os.environ:
    CONFIG_FILE = os.environ["CONFIG_FILE"]
with open(CONFIG_FILE) as f:
    CONFIG = json.load(f)

"""
###############################################################################
# F U N C T I O N S
###############################################################################
"""


async def getDeviceMetricsFromSNMP(
    server: str,
    port: int = 161,
    user: str = "readonly",
    password: str | None = None,
    authAlgorithm: str = "md5",
    encryptionPass: str | None = None,
    encryptionAlgorithm: str = "des",
    oidMapper: dict = {},
) -> dict | None:
    """
    getDeviceMetricsFromSNMP
    @desc: Loop over given OIDs and store values in a dictionary
    @param server, str: FQDN or IP address of the device to check
    @param port, int: The UDP Port for the SNMP request (default: 161)
    @param user, str: The user name to login to SNMP server (default: 'readonly')
    @param password, str|None: The users password to login to SNMP server (default: None)
    @param authAlgorithm, str: The authentication algorithm, supported methods are 'md5',
           'sha', 'sha224', 'sha256', 'sha384', 'sha512' (default: 'md5')
    @param encryptionPass, str|None: The password for the encryption (default: None)
    @param encryptionAlgorithm, str: The encryption algorithm, supported algorithms as
           'des', '3des', 'aes128', 'aes192', 'aes256' (default: 'des')
    @param oidMapper, dict: A dictionary of OIDs and the corresponding attribute name (default: {})
    @return: dict|None: The SNMP data
    """

    authProtocol = USM_AUTH_HMAC96_MD5
    if authAlgorithm.lower() == "md5":
        authProtocol = USM_AUTH_HMAC96_MD5
    elif authAlgorithm.lower() == "sha":
        authProtocol = USM_AUTH_HMAC96_SHA
    elif authAlgorithm.lower() == "sha224":
        authProtocol = USM_AUTH_HMAC128_SHA224
    elif authAlgorithm.lower() == "sha256":
        authProtocol = USM_AUTH_HMAC192_SHA256
    elif authAlgorithm.lower() == "sha384":
        authProtocol = USM_AUTH_HMAC256_SHA384
    elif authAlgorithm.lower() == "sha512":
        authProtocol = USM_AUTH_HMAC384_SHA512

    privProtocol = USM_PRIV_CBC56_DES
    if encryptionAlgorithm.lower() == "aes128":
        privProtocol = USM_PRIV_CFB128_AES
    elif encryptionAlgorithm.lower() == "aes192":
        privProtocol = USM_PRIV_CFB192_AES
    elif encryptionAlgorithm.lower() == "aes256":
        privProtocol = USM_PRIV_CFB256_AES
    elif encryptionAlgorithm.lower() == "des":
        privProtocol = USM_PRIV_CBC56_DES
    elif encryptionAlgorithm.lower() == "3des":
        privProtocol = USM_PRIV_CBC168_3DES

    userData = UsmUserData(
        userName=user, authKey=password, privKey=encryptionPass, authProtocol=authProtocol, privProtocol=privProtocol
    )

    # define dictionary that holds requested data
    DATA = {}

    for oid in oidMapper.keys():
        name = oidMapper[oid]
        log.debug(f"{name} {oid}")

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            SnmpEngine(),
            userData,
            await UdpTransportTarget.create((server, port)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        # check for errors
        if errorIndication:
            log.error(f"{errorIndication}")
            return None
        elif errorStatus:
            log.error(
                "{} at {}".format(errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or "?")
            )
            return None

        if varBinds == ():
            log.warning("Result is empty, skipping!")
            continue
        value = varBinds[0][1]
        log.debug(f"    {value}")
        if isinstance(value, pysnmp.proto.rfc1902.Integer):
            DATA[name] = int(value)
        elif isinstance(value, pysnmp.proto.rfc1902.Counter64):
            DATA[name] = int(value)
        elif isinstance(value, pysnmp.proto.rfc1902.OctetString):
            DATA[name] = str(value).strip()
        else:
            log.debug(f"    Type: {type(value)}")
            DATA[name] = str(value).strip()
    return DATA


def publishMQTT(client: mqtt.Client, topic: str, payload: dict, retain: bool = False) -> None:
    """
    publishMQTT - publish a payload to a MQTT topic
    @param client, paho.mqtt.client.Client(): The initialized MQTT client object
    @param topic, str(): The MQTT topic to publish the message to
    @param payload, dict(): The MQTT payload to publish to the topic
    @param retain, bool(): Use retain mode to publish data (default: False)
    """

    client.publish(topic, payload=str(payload), qos=0, retain=retain)

    return None


"""
###############################################################################
# M A I N
###############################################################################
"""

# initialize logger
log = logging.getLogger()
log_handler = logging.StreamHandler(sys.stdout)
if "DEBUG" not in CONFIG:
    log.setLevel(logging.INFO)
    log_handler.setLevel(logging.INFO)
else:
    if CONFIG["DEBUG"]:
        log.setLevel(logging.DEBUG)
        log_handler.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
        log_handler.setLevel(logging.INFO)
log_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log_handler.setFormatter(log_formatter)
log.addHandler(log_handler)

log.info("SNMP to MQTT processor v{} started".format(VERSION))

# set some defaults
if "mqtt" not in CONFIG:
    log.error("MQTT specific configuration is missing in {}".format(CONFIG))
if "tls" not in CONFIG["mqtt"]:
    CONFIG["mqtt"]["tls"] = False
if "client_id" not in CONFIG["mqtt"]:
    CONFIG["mqtt"]["client_id"] = None
if "hostname_validation" not in CONFIG["mqtt"]:
    CONFIG["mqtt"]["hostname_validation"] = True
if "protocol_version" not in CONFIG["mqtt"]:
    CONFIG["mqtt"]["protocol_version"] = 3

# ------------------------------------------------------------------------------
log.debug("Configure MQTT client:")
log.debug("- client_id={}".format(CONFIG["mqtt"]["client_id"]))
log.debug("- transport=tcp")
if CONFIG["mqtt"]["protocol_version"] == 5:
    log.debug("- protocol=MQTTv5")
    client = mqtt.Client(client_id=CONFIG["mqtt"]["client_id"], userdata=None, transport="tcp", protocol=mqtt.MQTTv5)
else:
    log.debug("- clean_session=True")
    log.debug("- protocol=MQTTv311")
    client = mqtt.Client(
        client_id=CONFIG["mqtt"]["client_id"],
        clean_session=True,
        userdata=None,
        transport="tcp",
        protocol=mqtt.MQTTv311,
    )

if (
    "user" in CONFIG["mqtt"]
    and CONFIG["mqtt"]["user"] != ""
    and "password" in CONFIG["mqtt"]
    and CONFIG["mqtt"]["password"] != ""
):
    log.debug("Set username ({}) and password for MQTT connection".format(CONFIG["mqtt"]["user"]))
    client.username_pw_set(CONFIG["mqtt"]["user"], password=CONFIG["mqtt"]["password"])

if CONFIG["mqtt"]["tls"]:
    log.debug("MQTT connection is TLS encrypted")
    client.tls_set(ca_certs=None, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
    if CONFIG["mqtt"]["hostname_validation"]:
        client.tls_insecure_set(False)
    else:
        client.tls_insecure_set(True)

# connect to MQTT server
log.debug("Connecting to MQTT server {}:{}".format(CONFIG["mqtt"]["server"], CONFIG["mqtt"]["port"]))
client.connect(CONFIG["mqtt"]["server"], CONFIG["mqtt"]["port"], 60)


# ------------------------------------------------------------------------------
# loop over devices
log.debug("loop over devices")

for device in CONFIG["devices"]:
    log.debug("Process device: {}".format(device))
    # load device configuration
    devConf = CONFIG[device]

    # get metrics from device
    payload = asyncio.run(
        getDeviceMetricsFromSNMP(
            server=devConf["server"],
            port=devConf["port"],
            user=devConf["snmpCredentials"]["user"],
            password=devConf["snmpCredentials"]["password"],
            authAlgorithm=devConf["snmpCredentials"]["algorithm"],
            encryptionPass=devConf["snmpEncryption"]["password"],
            encryptionAlgorithm=devConf["snmpEncryption"]["algorithm"],
            oidMapper=devConf["snmpOID2Attribute"],
        )
    )
    if not payload:
        log.debug("No SNMP data found to publish. Continue with next device")
        continue

    # check if there is an additional parameter calculation
    if "parameterCalculation" in devConf.keys() and isinstance(devConf["parameterCalculation"], list):
        for param in devConf["parameterCalculation"]:
            payload[param + "LifetimePCT"] = round(payload[param + "Left"] * 100 / payload[param + "Max"], 1)
            log.debug("{} LifetimePCT {}%".format(param, payload[param + "LifetimePCT"]))

    # adding timestamp
    payload["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z")

    # publish metrics to MQTT
    payload = json.dumps(payload)
    log.debug("Publish data to MQTT")
    log.debug("  topic: {}".format(devConf["mqttTopic"]))
    log.debug("  payload: {}".format(payload))

    publishMQTT(client=client, topic=devConf["mqttTopic"], payload=payload, retain=CONFIG["mqtt"]["retain"])

log.debug("Disconnect from MQTT server")
client.disconnect()

log.info("SNMP to MQTT processor v{} stopped".format(VERSION))
sys.exit()
