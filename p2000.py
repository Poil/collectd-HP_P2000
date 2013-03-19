# -*- coding: utf-8 -*-
import collectd
import hashlib
import socket
import urllib2
from lxml import etree


class P2000(object):
    def __init__(self):
        self.plugin_name = 'P2000'
        self.host = None
        self.address = None
        self.myhash = None
        self.user = None
        self.password = None
        self.ssl = None
        self.enclosureInfo = True
        self.controllerInfo = True
        self.vdiskInfo = True
        self.diskInfo = True
        self.volInfo = True
        self.timeout = 15
        self.handler = urllib2.HTTPHandler(debuglevel=0)
        self.opener = urllib2.build_opener(self.handler)

    def submit(self, value, plugin_instance=None, type=None, type_category=None, type_instance=None):
        v = collectd.Values()
        v.host = self.host
        v.plugin = self.plugin_name

        if plugin_instance:
            v.plugin_instance = plugin_instance.replace('-', '_')

        v.type = type
        if type_category:
            v.type_instance = type_category.replace('-', '_').replace('.', '_') + '-' + type_instance.replace('-', '_').replace('.', '_')
        else:
            v.type_instance = type_instance.replace('-', '_').replace('.', '_')

        v.values = [value, ]
        v.dispatch()

    def makeCall(self, command):
        url = ('https://' if self.ssl else 'http://') + self.address + '/api/'
        req = urllib2.Request(url + command)
        res = self.opener.open(req)
        reponse = res.read()
        return etree.XML(reponse)

    def login(self):
        if self.myhash:
            authToken = self.myhash
        else:
            collectd.info(self.user + '_' + self.password)
            authToken = hashlib.md5(self.user + '_' + self.password).hexdigest()
        root = self.makeCall('login/' + authToken)
        status = root.findtext(".//PROPERTY[@name='response-type-numeric']")
        token = root.findtext(".//PROPERTY[@name='response']")
        return token if status == '0' else None

    def processEnclosureStatus(self, root):
        enclosureId = 0
        for obj in root:
            objectName = obj.get('name')
            if objectName == 'enclosure-environmental':
                enclosureId += 1
                # next enclosure found
                #for prop in obj:
                #    print prefix + 'Enclosure[%d].%s=%s' % (enclosureId, prop.get('name'), prop.text)
            elif objectName == 'enclosure-component':
                unitNumber = int(obj.findtext('./PROPERTY[@name="enclosure-unit-number"]'))
                unitType = obj.findtext('./PROPERTY[@name="type"]')
                for prop in obj:
                    name = prop.get('name')
                    if name in ('enclosure-unit-number', 'type'):
                        continue
                    value = prop.text
                    if name == 'additional-data':
                        name = 'current-value'
                        if '=' in value:
                            value = float(prop.text.split('=')[1].split()[0])
                    #print prefix + 'Enclosure[%d].%s[%d].%s=%s' % (enclosureId, unitType, unitNumber, name, value)
                    if unitType == 'Temp' and name == 'current-value':
                        self.submit(type='temperature', type_instance=name, type_category=str(unitNumber), value=value)
                    elif unitType == 'Voltage' and name == 'current-value':
                        self.submit(type='voltage', type_instance=name, type_category=str(unitNumber), value=value)

    def processStatistics(self, root, objectClass, objectName, durableIdName):
        for obj in root.findall('./OBJECT[@name="%s"]' % objectName):
            durableId = obj.findtext('./PROPERTY[@name="%s"]' % durableIdName)
            for prop in obj:
                name = prop.get('name')
                if name == durableIdName:
                    continue
                #print prefix + '%s[%s].%s=%s' % (objectClass, durableId, name, prop.text)
                if objectClass in ['Disk', 'VDisk', 'Volume', 'Controller']:
                    if name in ['data-written-numeric', 'data-read-numeric', 'write-cache-hits', 'write-cache-misses', 'read-cache-hits', 'read-cache-misses', 'small-destages', 'full-stripe-write-destages']:
                        self.submit(plugin_instance=objectClass, type='counter', type_category=name, type_instance=durableId, value=prop.text)
                    elif name in ['read-ahead-operations']:
                        self.submit(plugin_instance=objectClass, type='operations', type_category=durableId, type_instance=name, value=prop.text)
                    elif name in ['number-of-reads', 'number-of-writes']:
                        self.submit(plugin_instance=objectClass, type='counter', type_category=durableId, type_instance=name, value=prop.text)
                    elif name == 'bytes-per-second-numeric':
                        self.submit(plugin_instance=objectClass, type='bytes', type_category=name, type_instance=durableId, value=prop.text)
                    elif name == 'iops':
                        self.submit(plugin_instance=objectClass, type='disk_ops_complex', type_category=name, type_instance=durableId, value=prop.text)
                    elif name in ['smart-count-1', 'io-timeout-count-1', 'no-response-count-1', 'spinup-retry-count-1', 'number-of-media-errors-1', 'number-of-nonmedia-errors-1', 'number-of-block-reassigns-1', 'number-of-bad-blocks-1', 'smart-count-2', 'io-timeout-count-2', 'no-response-count-2', 'spinup-retry-count-2', 'number-of-media-errors-2', 'number-of-nonmedia-errors-2', 'number-of-block-reassigns-2', 'number-of-bad-blocks-2']:
                        self.submit(plugin_instance=objectClass, type='gauge', type_category=durableId, type_instance=name, value=prop.text)
                    elif name == 'write-cache-percent':
                        self.submit(plugin_instance=objectClass, type='percent', type_category=durableId, type_instance=name, value=prop.text)

    def processControllerStatistics(self, root):
        self.processStatistics(root, 'Controller', 'controller-statistics', 'durable-id')

    def processDiskStatistics(self, root):
        self.processStatistics(root, 'Disk', 'disk-statistics', 'durable-id')

    def processVDiskStatistics(self, root):
        self.processStatistics(root, 'VDisk', 'vdisk-statistics', 'name')

    def processVolumeStatistics(self, root):
        self.processStatistics(root, 'Volume', 'volume-statistics', 'volume-name')

    def config(self, obj):
        """Received configuration information"""
        for node in obj.children:
            if node.key == 'Host':
                self.host = node.values[0]
            elif node.key == 'Address':
                self.address = node.values[0]
            elif node.key == 'Hash':
                self.myhash = node.values[0]
            elif node.key == 'User':
                self.user = node.values[0]
            elif node.key == 'Password':
                self.password = node.values[0]
            elif node.key == 'NoSSL':
                self.ssl = int(node.values[0])
            elif node.key == 'Timeout':
                self.timeout = node.values[0]
            elif node.key == 'Verbose':
                self.verbose = bool(node.values[0])
            elif node.key == 'DiskInfo':
                self.diskInfo = bool(node.values[0])
            elif node.key == 'VolInfo':
                self.volInfo = bool(node.values[0])
            elif node.key == 'VdiskInfo':
                self.vdiskInfo = bool(node.values[0])
            elif node.key == 'EnclosureInfo':
                self.enclosureInfo = bool(node.values[0])
            elif node.key == 'ControllerInfo':
                self.controllerInfo = bool(node.values[0])
            else:
                collectd.warning('P2000 plugin: Unknown config key: %s.' % node.key)
        if self.myhash:
            collectd.info('Configured with address=%s, hash=%s, ssl=%s, timeout=%s' % (self.address, self.myhash, self.ssl, self.timeout))
        else:
            collectd.info('Configured with address=%s, user=%s, password=%s, ssl=%s, timeout=%s' % (self.address, self.user, self.password, self.ssl, self.timeout))

    def do_server_status(self):
        socket.setdefaulttimeout(self.timeout)
        token = self.login()
        if token:
            self.opener.addheaders.append(('Cookie', 'wbisessionkey=' + token))
        if self.enclosureInfo:
            self.processEnclosureStatus(self.makeCall('show/enclosure-status'))
        if self.controllerInfo:
            self.processControllerStatistics(self.makeCall('show/controller-statistics'))
        if self.diskInfo:
            self.processDiskStatistics(self.makeCall('show/disk-statistics'))
        if self.vdiskInfo:
            self.processVDiskStatistics(self.makeCall('show/vdisk-statistics'))
        if self.volInfo:
            self.processVolumeStatistics(self.makeCall('show/volume-statistics'))
        self.makeCall('logout')


p2000 = P2000()
collectd.register_config(p2000.config)
collectd.register_read(p2000.do_server_status)
