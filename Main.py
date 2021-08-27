from pysnmp.hlapi import *
from pysnmp.smi.rfc1902 import ObjectIdentity
from pyasn1.type.univ import OctetString
import binascii


def request(req, oid, ip, min, max):

    value = []
    i = min

    if req == 'bulkCmd':
        request = globals()[req](
            SnmpEngine(),
            CommunityData('public', mpModel=0),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            min,
            max,
            ObjectType(ObjectIdentity(oid))
        )
    else:
        request = globals()[req](
            SnmpEngine(),
            CommunityData('public', mpModel=0),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            # min,
            # max,
            ObjectType(ObjectIdentity(oid))
        )
    print(0)

    for errorIndication, errorStatus, errorIndex, varBinds in request:
        if max == 1:
            return varBinds
        elif i>=max:
            return value
        i += 1

        if errorIndication:
            print(errorIndication)

        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

        else:
            for varBind in varBinds:
                print(' = '.join([x.prettyPrint() for x in varBind]))

        value.append(varBinds)

    print(1)
    return value


def main():

    ip = '172.17.32.4'
    dot1dTpFdbStatus = '1.3.6.1.2.1.17.7.1.2.1.1.2'
    dot1dTpFdbAddress = '1.3.6.1.2.1.17.4.3.1.1'
    dot1dTpFdbPort = '1.3.6.1.2.1.17.4.3.1.2'

    mac_count = request('nextCmd', dot1dTpFdbStatus, ip, 0, 1)[0]
    print(mac_count.prettyPrint())

    last_FdbAddress, macs = request(
        'bulkCmd', dot1dTpFdbAddress, ip, 0, mac_count)[0]
    # hex_mac = OctetString(mac).asOctets()
    print(3)

    last_TpFdbPort, ports = request('bulkCmd', dot1dTpFdbPort, ip, 0, 1)[0]
    # print(last_FdbAddress, '--', hex_mac.hex(':'), '||', last_TpFdbPort, '--', ports)

    return(macs)


mac = main()

for i in mac:
    for x in i:
        print(x)
