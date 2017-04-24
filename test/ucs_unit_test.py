from __future__ import absolute_import
import unittest

from mock import MagicMock
from zeus import client

from test.config.config import ZEUS_TOKEN, ZEUS_SERVER, LOG_LEVEL
from test.test_data.ucs_unit_test_data import dn_dict, event_str_list, class_ids
from ucs_agent import UCSAgent


class UCSTest(unittest.TestCase):
    def setUp(self):
        self.ucs_agent = UCSAgent()
        self.ucs_agent.set_log_level(LOG_LEVEL)
        self.ucs_agent.zeus_client = client.ZeusClient(ZEUS_TOKEN, ZEUS_SERVER)
        self.original_get_dn_conf = UCSAgent.get_dn_conf

    # test submit data to zeus.
    def test_submit(self):
        UCSAgent.get_dn_conf = MagicMock()
        for class_id in class_ids:
            response = self.ucs_agent.add_log("info", "ucs", msg=[dn_dict])
            # if name checking is correct, assert the return
            # else, a error will occur
            if response:
                self.assertEqual(response[0], 200)

    # test submit async events
    def test_submit_event(self):
        event_str = ''
        for i in range(len(event_str_list)):
            event_str += event_str_list[i]

            str_list = event_str.split("\n", 1)
            length = int(str_list[0])
            self.ucs_agent.submit_async_events(event_str_list[i])
            self.assertLessEqual(len(self.ucs_agent.event_string), length,
                                 msg="Event's length must equal or less than"
                                     "length, otherwise,"
                                     "it should be sent already.")
            event_str = self.ucs_agent.event_string

    def tearDown(self):
        # UCSPlugin.get_args = self.original_get_args
        UCSAgent.get_dn_conf = self.original_get_dn_conf
