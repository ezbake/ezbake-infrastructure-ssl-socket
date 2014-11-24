#   Copyright (C) 2013-2014 Computer Sciences Corporation
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
UnitTests
"""

import nose.tools as nt
from pkg_resources import resource_filename
import os
import random
import threading


from ezbake.transport.EzBakeInfrastructureSSLSocket import EzSSLSocket, EzSSLServerSocket
from testservice import TestService

from thrift.server import TServer
from thrift.protocol import TBinaryProtocol


CERTS_DIR = resource_filename('tests', 'certs')
CA_CERT = os.path.join(CERTS_DIR, 'ezbakeca.crt')
CLIENT_CRT = os.path.join(CERTS_DIR, 'client.crt')
CLIENT_KEY = os.path.join(CERTS_DIR, 'client.key')
SERVER_CRT = os.path.join(CERTS_DIR, 'server.crt')
SERVER_KEY = os.path.join(CERTS_DIR, 'server.key')



class TestEzSSLSocket(object):
    """Main Test Class
    Note: A thrift simple sever is created for every test case
    """

    def setUp(self):
        """Set up test - create a server with EzSSL Server Socket"""

        self.testport = random.randint(40000, 65530)
        self.server = TServer.TSimpleServer(TestService.Processor(self),
                                            EzSSLServerSocket(host='localhost', 
                                                              port=self.testport,
                                                              certfile=SERVER_CRT,
                                                              ca_certs=CA_CERT,
                                                              keyfile=SERVER_KEY))
        self.serverThread = threading.Thread(target=TServer.TSimpleServer.serve, args=(self.server,))
        self.serverThread.setDaemon(True)
        self.serverThread.start()

    def tearDown(self):
        """Tear down test"""
        pass

    def ping(self):
        """Thrift processor handler callback for our TestService thrift service"""
        return True

    def test_socketConnect(self):
        """Test Case - create new Ez SSL connection to server running of different thread"""
        transport = EzSSLSocket(host='localhost',
                                port=self.testport,
                                keyfile=CLIENT_KEY,
                                ca_certs=CA_CERT,
                                certfile=CLIENT_CRT)
        client = TestService.Client(TBinaryProtocol.TBinaryProtocol(transport))

        transport.open()
        nt.eq_(True, client.ping())


