# Quick reference

Maintained by: [Michael Oberdorf IT-Consulting](https://www.oberdorf-itc.de/)

Source code: [GitHub](https://github.com/cybcon/docker.snmp2mqtt)

Container image: [DockerHub](https://hub.docker.com/r/oitc/snmp2mqtt)

# Supported tags and respective `Dockerfile` links

* [`latest`, `1.0.3`](https://github.com/cybcon/docker.snmp2mqtt/blob/v1.0.3/Dockerfile)
* [`1.0.2`](https://github.com/cybcon/docker.snmp2mqtt/blob/v1.0.2/Dockerfile)
* [`1.0.1`](https://github.com/cybcon/docker.snmp2mqtt/blob/v1.0.1/Dockerfile)
* [`1.0.0`](https://github.com/cybcon/docker.snmp2mqtt/blob/v1.0.0/Dockerfile)

# Summary
The container image is based on Alpine Linux with python3 interpreter.
The tool is written in python and connects to a MQTT server. After that, it loops over the configured SNMP endpoints and graps the configured OIDs.
The collected SNMP data will be transformed as a json object and published to the given MQTT topic.

# Configuration
## Container configuration

The container reads some configuration via environment variables.

| Environment variable name    | Description                                                                                    | Required     | Default value             |
|------------------------------|------------------------------------------------------------------------------------------------|--------------|---------------------------|
| `CONFIG_FILE`                | The configuration file that contains the connection parameters to MQTT and the SNMP endpoints. | **OPTIONAL** | `/app/etc/snmp2mqtt.json` |


## Configuration file

The path and filename to the general configuration file can be set via environment variable `CONFIG_FILE`. By default, the script will use `/app/etc/snmp2mqtt.json`.

Inside this file we need to configure the MQTT server connection parameters and the SNMP endpoint connection parameters.

### Example

```json
{
  "DEBUG": true,
  "devices": [
    "EXAMPLE"
  ],
  "mqtt": {
    "client_id": "snmp2mqtt",
    "user": "snmp2mqtt",
    "password": "myMQTTPassword",
    "server": "test.mosquitto.org",
    "port": 1883,
    "tls": false,
    "retain": true,
    "hostname_validation": false,
    "protocol_version": 3
    },
  "EXAMPLE": {
    "server": "127.0.0.1",
    "port": 161,
    "snmpCredentials": {
      "user": "snmpUser",
      "password": "snmpPassword",
      "algorithm": "MD5"
    },
    "snmpEncryption": {
      "password": "snmpEncryptionKey",
      "algorithm": "DES"
    },
    "snmpOID2Attribute": {
      "1.3.6.1.4.1.2021.4.3.0": "memTotalSwap"
    },
    "mqttTopic": "de/oberdorf-itc/devices/EXAMPLE"
  }
}
```

### Field description

| Field                                      | Type    | Description                                                                                                |
|--------------------------------------------|---------|------------------------------------------------------------------------------------------------------------|
| `DEBUG`                                    | Boolean | Enable debug output on stdout                                                                              |
| `devices`                                  | Array   | A List of names that represent SNMP endpoints. These keywords are later used inside the configuation file. |
| `mqtt`                                     | Object  | Contains MQTT specific configuration parameters.                                                           |
| `mqtt.client_id`                           | String  | The MQTT client identifier.                                                                                |
| `mqtt.user`                                | String  | The username to authenticate to the MQTT server.                                                           |
| `mqtt.password`                            | String  | The password to authenticate to the MQTT server.                                                           |
| `mqtt.server`                              | String  | IP address or FQDN of the MQTT server.                                                                     |
| `mqtt.port`                                | String  | The TCP port number of the MQTT server.                                                                    |
| `mqtt.tls`                                 | Boolean | If a TLS encrpted communication should be established or not.                                              |
| `mqtt.hostname_validation`                 | Boolean | Validate the hostname from the servercertificate or not.                                                   |
| `mqtt.protocol_version`                    | Integer | The MQTT protocol version. Can be 3 (for MQTTv311) or 5 (for MQTTv5).                                      |
| *\<device\>*                               | Object  | Contains the SNMP endpoint specific configuration parametes.                                               |
| *\<device\>*.`server`                      | String  | IP address or FQDN of the SNMP endpoint.                                                                   |
| *\<device\>*.`port`                        | Integer | The TCP port number of the SNMP endpoint.                                                                  |
| *\<device\>*.`snmpCredentials`             | Object  | The SNMP endpoint credentials for authentication.                                                          |
| *\<device\>*.`snmpCredentials.user`        | String  | The username to authenticate to the SNMP endpoint.                                                         |
| *\<device\>*.`snmpCredentials.password`    | String  | The password to authenticate to the SNMP endpoint.                                                         |
| *\<device\>*.`snmpCredentials.algorithm`   | String  | The algorithm to use when authenticating to the SNMP endpoint (supported: `MD5` or `SHA`).                 |
| *\<device\>*.`snmpEncryption`              | Object  | The SNMP endpoint data encrption parameters.                                                               |
| *\<device\>*.`snmpEncryption.password`     | String  | The SNMP data encrption password.                                                                          |
| *\<device\>*.`snmpEncryption.algorithm`    | String  | The SNMP data encrption algorithm (supported: `DES`).                                                      |
| *\<device\>*.`snmpOID2Attribute`           | Object  | List of SNMP OIDs and a human readable name.                                                               |
| *\<device\>*.`snmpOID2Attribute`.*\<OID\>* | String  | A human readable translation of the given OID.                                                             |
| *\<device\>*.`mqttTopic`                   | String  | the MQTT topic to publish the colected device data.                                                        |


# Running the container image

```
docker run --rm -v ./myConfig.json:/app/etc/snmp2mqtt.json:ro oitc/snmp2mqtt:latest
```

# Docker compose configuration

```yaml
version: '3.8'

services:
  snmp2mqtt:
    container_name: snmp2mqtt
    image: oitc/snmp2mqtt:1.0.0
    restart: "no"
    user: 3917:3917
    volumes:
      - /srv/docker/snmp2mqtt/etc/snmp2mqtt.json:/app/etc/snmp2mqtt.json:ro
```

# Donate
I would appreciate a small donation to support the further development of my open source projects.

<a href="https://www.paypal.com/donate/?hosted_button_id=BHGJGGUS6RH44" target="_blank"><img src="https://raw.githubusercontent.com/stefan-niedermann/paypal-donate-button/master/paypal-donate-button.png" alt="Donate with PayPal" width="200px"></a>

# License

Copyright (c) 2023 Michael Oberdorf IT-Consulting

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
