#!/usr/bin/env python
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

from setuptools import setup, find_packages

setup(
    name='ezbake-infrastructure-ssl-socket',
    version='2.0',
    description='A python library for a thrift SSL Socket (server & client) that validates the peer\'s certificate',
    author='Ope Arowojolu',
    author_email='oarowojolu@42six.com',
    url='https://github.com/ezbake/ezbake-infrastructure-ssl-socket',
    packages=find_packages('lib'),
    package_dir={'': 'lib'},
    install_requires=['thrift == 0.9.1']
)

