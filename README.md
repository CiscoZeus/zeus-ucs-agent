# UCS(Unified Computing System) Agent


UCS agent supports to collect data from Cisco Unified Computing System managed server. First of all, UCS agent will retrieve the data of UCS objects by Distinguished name(Dn) and send them to Zeus server. After retrieving data, UCS agent will listen to UCS's asynchronous events, and submit the events to Zeus server asynchronously.  

## Dependencies

Before using UCS agent, there are some dependencies need to be installed. 

If [pip](https://pip.pypa.io/en/stable/)  has not installed, please [install pip](https://pip.pypa.io/en/stable/installing/) before the following dependencies.

* [pycurl](http://pycurl.io/)

        pip install pycurl
        

* [xmltodict](https://pypi.python.org/pypi/xmltodict)

        pip install xmltodict
        
* [ucsmsdk](https://github.com/CiscoUcs/ucsmsdk)
    
        pip install ucsmsdk

    
* [zeus python client](https://github.com/CiscoZeus/python-zeusclient)
    
        pip install cisco-zeus


## Installation
 
 There is no need to install ucs_agent, just download it and run it directly.
 
    $ git clone https://github.com/CiscoZeus/zeus-ucs-agent.git
    $ cd zeus-ucs-agent
    $ python ucs_agent.py # optional arguments specified.

## Configuration
#### Configuration can be done by config file or CLI.

There are two ways to configure UCS agent, by config.py and CLI. If we don't specified arguments by CLI, the argument will be the default value which has been defined by config.py. 

* Config.py
    
        UCS = "<UCS Manager IP address in double quotes>"
        UCS_USER = "<UCS Manager user name in double quotes>"
        UCS_PASSWD = "<UCS Manager password in double quotes>"
        
        COUNT = 5000
        
        IS_SECURE = True
        PORT = 443
        
        LOG_LEVEL = "INFO"
        
        ZEUS_TOKEN = "<INSERT_TOKEN_HERE>"
        ZEUS_SERVER = "<Zeus API URL in double quotes>"

* CLI

        usage: ucs_agent.py [-h] [-c [UCS]] [-C [COUNT]] [-u [USER]] [-p [PASSWORD]]
                            [-s [SECURE]] [-P [PORT]] [-l [LOG_LEVEL]] [-t [TOKEN]]
                            [-z [ZEUS]]
        optional arguments:
          -h, --help            show this help message and exit
          -c [UCS], --ucs [UCS]
                                IP or host name of unified computing system managed
                                server. (default: <UCS Manager IP address in double
                                quotes>)
          -C [COUNT], --Count [COUNT]
                                Count of records in one log list. (default: 5000)
          -u [USER], --user [USER]
                                User name of UCS. (default: <UCS Manager user name in
                                double quotes>)
          -p [PASSWORD], --password [PASSWORD]
                                Password of UCS (default: <UCS Manager password in
                                double quotes>)
          -s [SECURE], --secure [SECURE]
                                Secure of connection. (default: True)
          -P [PORT], --port [PORT]
                                Port of TCP socket. (default: 443)
          -l [LOG_LEVEL], --log_level [LOG_LEVEL]
                                Level of log: CRITICAL, ERROR, WARN, WARNING,INFO,
                                DEBUG, NOTSET (default: INFO)
          -t [TOKEN], --token [TOKEN]
                                Token of ZEUS API.
          -z [ZEUS], --zeus [ZEUS]
                                IP or host name of ZEUS server. (default: <Zeus API
                                URL in double quotes>)


## Collected Data
UCS agent collects many kinds of data, including:

* fault
    * faultInst

* performance
    * swSystemStats,
    * etherTxStats,
    * etherPauseStats,
    * etherRxStats,
    * etherErrStats,
    * adaptorVnicStats,
    * equipmentPsuStats,
    * processorEnvStats,
    * computeMbTempStats,
    * computeMbPowerStats,
    * equipmentChassisStats

* inventory
    * firmwareRunning,
    * storageLocalDisk,
    * vnicEtherIf,
    * lsServer,
    * fabricVsan,
    * fabricVlan,
    * fabricEthLanPcEp,
    * fabricEthLanPc,
    * etherPIo,
    * fabricDceSwSrvEp,
    * computeBlade,
    * equipmentPsu,
    * equipmentChassis,
    * equipmentSwitchCard,
    * equipmentIOCard,
    * topSystem,
    * computeRackUnit

## Event listening

UCS agent also supports to listen to UCS's asynchronous events, and submit them to Zeus server.

## Copyright
#### Copyright
Copyright(C) 2017 - @Cisco Systems, Inc.

#### License
Apache License, Version 2.0
