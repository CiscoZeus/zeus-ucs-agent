# -*- coding: utf-8 -*-
# Copyright 2017 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
import logging
import pycurl
import re
import threading
from time import sleep

import argparse
import xmltodict
from ucsmsdk import ucsgenutils
from ucsmsdk import ucsmethodfactory
from ucsmsdk.ucshandle import UcsHandle
from ucsmsdk.ucsmethod import ExternalMethod
from ucsmsdk.ucsmo import ManagedObject
from zeus import client

import config as conf


class UCSAgent(object):
    def __init__(self):
        super(UCSAgent, self).__init__()
        self.url = ''
        self.user = ''
        self.passwd = ''
        self.cookie = ''

        self.zeus_client = None
        self.zeus_server = ''
        self.token = ''

        self.listener = None
        self.event_string = ''

        self.class_ids = []
        self.dn_set = set()
        self.fault = ["faultInst"]

        self.performance = ["swSystemStats",
                            "etherTxStats",
                            "etherPauseStats",
                            "etherRxStats",
                            "etherErrStats",
                            "adaptorVnicStats",
                            "equipmentPsuStats",
                            "processorEnvStats",
                            "computeMbTempStats",
                            "computeMbPowerStats",
                            "equipmentChassisStats"]

        self.inventory = ["firmwareRunning",
                          "storageLocalDisk",
                          "vnicEtherIf",
                          "lsServer",
                          "fabricVsan",
                          "fabricVlan",
                          "fabricEthLanPcEp",
                          "fabricEthLanPc",
                          "etherPIo",
                          "fabricDceSwSrvEp",
                          "computeBlade",
                          "equipmentPsu",
                          "equipmentChassis",
                          "equipmentSwitchCard",
                          "equipmentIOCard",
                          "topSystem",
                          "computeRackUnit"]

        self.class_ids.extend(self.fault)
        self.class_ids.extend(self.performance)
        self.class_ids.extend(self.inventory)

    def get_args(self):
        # read arguments from command line parameters
        parser = argparse.ArgumentParser()
        parser.add_argument("-c", "--ucs", nargs="?", type=str, default=conf.UCS,
                            help="""IP or host name of unified computing system managed server.
                                    \n(default: %s)""" % conf.UCS)

        parser.add_argument("-u", "--user", nargs="?", type=str,
                            default=conf.UCS_USER,
                            help="User name of UCS. \n(default: %s)" % conf.UCS_USER)

        parser.add_argument("-p", "--password", nargs="?", type=str,
                            default=conf.UCS_PASSWD,
                            help="Password of UCS \n(default: %s)" % conf.UCS_PASSWD)

        parser.add_argument("-s", "--secure", nargs="?", type=bool,
                            default=conf.IS_SECURE,
                            help="Secure of connection. \n(default: %s)" % conf.IS_SECURE)

        parser.add_argument("-P", "--port", nargs="?", type=int,
                            default=conf.PORT,
                            help="Port of TCP socket. \n(default: %d)" % conf.PORT)

        parser.add_argument("-l", "--log_level", nargs="?", type=str,
                            default=conf.LOG_LEVEL,
                            help="Level of log: CRITICAL, ERROR, WARN, WARNING,"
                                 "INFO, DEBUG, NOTSET \n(default: %s)" % conf.LOG_LEVEL)

        parser.add_argument("-t", "--token", nargs="?", type=str,
                            default=conf.ZEUS_TOKEN,
                            help="Token of ZEUS API.")

        parser.add_argument("-z", "--zeus", nargs="?", type=str,
                            default=conf.ZEUS_SERVER,
                            help="""IP or host name of ZEUS server.
                                    \n(default: %s)""" % conf.ZEUS_SERVER)
        args = parser.parse_args()
        return args

    def check_level(self, loglevel):
        level = getattr(logging, loglevel.upper(), None)
        if not isinstance(level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        return level

    def set_log_level(self, loglevel):
        level = self.check_level(loglevel)
        logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
                            level=level)
        self.logger = logging.getLogger("USC-Agent")

    def submit(self, msg, name="ucs"):
        # check name: All log names must have only letter and numbers
        if re.match('^[A-Za-z0-9]+$', name):
            # send log to zeus.
            return self.zeus_client.sendLog(name, [msg])
        else:
            self.logger.error("""Name error: %s.
                              All log names must have only letter
                              and numbers (A-Za-z0-9).""" % name)
            return None

    def add_log(self, loglevel, name, msg, *args):
        level = self.check_level(loglevel)
        if self.logger.isEnabledFor(level):
            self.logger._log(level, msg, args)

        # submit data to zeus
        return self.submit(msg)

    def to_json(self, dn):
        # return the json dict
        dict = {'class_id': dn._class_id}
        if isinstance(dn, ExternalMethod):
            for prop, prop_value in sorted(ucsgenutils.iteritems(dn.__dict__)):
                filter = ManagedObject.__dict__['_ManagedObject__internal_prop']
                if prop in filter or prop.startswith("_ManagedObject__"):
                    continue

                if "ExternalMethod" in prop:
                    continue
                else:
                    dict[prop] = prop_value

            return dict

        if isinstance(dn, ManagedObject):
            for prop, prop_value in sorted(ucsgenutils.iteritems(dn.__dict__)):
                filter = ManagedObject.__dict__['_ManagedObject__internal_prop']
                if prop in filter or prop.startswith("_ManagedObject__"):
                    continue

                if prop in dn.__dict__['_ManagedObject__xtra_props']:
                    prop = "[X]" + str(prop)
                    dict[prop] = prop_value
                else:
                    dict[prop] = prop_value

            return dict

    def get_dn_conf(self):
        for class_id in self.class_ids:
            xml_req = ucsmethodfactory.config_find_dns_by_class_id(
                self.handler.cookie, class_id, in_filter=None)
            self.dn_obj_list = self.handler.process_xml_elem(xml_req)

            for dn in self.dn_obj_list:
                dn_config = self.handler.query_dn(dn.value)

                # use the self.to_json temporary until ucsmsdk provides this method.
                self.add_log("info", dn._class_id, msg=self.to_json(dn_config))
                self.dn_set.add(dn.value)

    def submit_async_events(self, response):
        self.event_string += response
        while len(self.event_string) > 0:
            str_list = self.event_string.split("\n", 1)
            length = int(str_list[0])
            event_str = str_list[1]
            if len(event_str) >= length:
                event = event_str[:length]

                # convert xml str to json and send to zeus.
                self.add_log("info", "event", json.dumps(xmltodict.parse(event)))

                # new event string starts from the end of last event.
                self.event_string = event_str[length:]
            else:
                # wait for entire content.
                break

    def subscribe_events(self):
        self.listener = pycurl.Curl()

        post_data = """<eventSubscribe cookie="%s"/>""" % self.cookie
        self.listener.setopt(self.listener.POSTFIELDS, post_data)
        self.listener.setopt(self.listener.URL, self.url)
        self.listener.setopt(self.listener.WRITEFUNCTION,
                             self.submit_async_events)

        self.listener.setopt(pycurl.SSL_VERIFYPEER, 0)
        self.listener.setopt(pycurl.SSL_VERIFYHOST, 0)

        self.listener.perform()

    def unsubscribe_events(self):
        xml_req = ucsmethodfactory.event_unsubscribe(self.handler.cookie)
        res = self.handler.process_xml_elem(xml_req)
        self.add_log("info", res._class_id, msg=self.to_json(res))

    def event_loop(self):
        # Maintain a client to listen to UCS's async notification.
        # when receive events, sent them to zeus.
        try:
            self.sub_thread = threading.Thread(target=self.subscribe_events)
            self.sub_thread.setDaemon(True)
            self.sub_thread.start()
            while threading.activeCount() > 0:
                sleep(1)
        except KeyboardInterrupt:
            self.logger.info("KeyboardInterrupt")
        finally:
            self.unsubscribe_events()

    def set_up(self):
        # get arguments
        self.args = self.get_args()
        self.host = self.args.ucs
        if self.args.secure == True:
            self.url = 'https://%s/nuova' % self.args.ucs
        else:
            self.url = 'http://%s/nuova' % self.args.ucs
        self.user = self.args.user
        self.passwd = self.args.password

        self.token = self.args.token
        self.zeus_server = self.args.zeus

        # set log level
        self.set_log_level(self.args.log_level)

        # set up a Zeus client to submit log to Zeus.
        self.zeus_client = client.ZeusClient(self.token, self.zeus_server)

        # set up a http client to UCS server.
        self.handler = UcsHandle(self.host, self.user, self.passwd,
                                 port=self.args.port, secure=self.args.secure)
        # login to ucs
        self.handler.login(auto_refresh=True)
        self.add_log("info", "aaaLogin",
                     msg={"User": self.user, "Password": self.passwd,
                          "cookie": self.handler.cookie})
        self.get_dn_conf()
        self.event_loop()

    def close(self):
        self.handler.logout()
        self.add_log('info', 'aaaLogout',
                     msg={"User": self.user, "Password": self.passwd,
                          "cookie": self.handler.cookie})


if __name__ == "__main__":
    ucs_plugin = UCSAgent()
    ucs_plugin.set_up()
    ucs_plugin.close()
