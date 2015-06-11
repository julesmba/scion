# Copyright 2015 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`opaque_field_test` --- SCION opaque field tests
=====================================================
"""
# Stdlib
import struct
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    OpaqueFieldType,
    OpaqueField,
    TRCField,
)


class TestOpaqueFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueField.__init__
    """
    def test_basic(self):
        op_fld = OpaqueField()
        ntools.eq_(op_fld.info, 0)
        ntools.eq_(op_fld.type, 0)
        ntools.assert_false(op_fld.parsed)
        ntools.assert_true(op_fld.raw is None)


class TestOpaqueFieldIsRegular(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueField.is_regular
    """
    def test_basic(self):
        op_fld = OpaqueField()
        op_fld.info = 0b10111111
        ntools.assert_true(op_fld.is_regular())

    def test_set(self):
        op_fld = OpaqueField()
        op_fld.info = 0b01000000 
        ntools.assert_false(op_fld.is_regular())


class TestOpaqueFieldIsContinue(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueField.is_continue
    """
    def test_basic(self):
        op_fld = OpaqueField()
        op_fld.info = 0b11011111
        ntools.assert_false(op_fld.is_continue())

    def test_set(self):
        op_fld = OpaqueField()
        op_fld.info = 0b00100000
        ntools.assert_true(op_fld.is_continue())


class TestOpaqueFieldIsXovr(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueField.is_xovr
    """
    def test_basic(self):
        op_fld = OpaqueField()
        op_fld.info = 0b11101111
        ntools.assert_false(op_fld.is_xovr())

    def test_set(self):
        op_fld = OpaqueField()
        op_fld.info = 0b00010000
        ntools.assert_true(op_fld.is_xovr())


class TestHopOpaqueFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.__init__
    """
    def test_basic(self):
        hop_op_fld = HopOpaqueField()
        ntools.eq_(hop_op_fld.exp_time, 0)
        ntools.eq_(hop_op_fld.ingress_if, 0)
        ntools.eq_(hop_op_fld.egress_if, 0)
        ntools.eq_(hop_op_fld.mac, b'\x00'*3)
        ntools.assert_false(hop_op_fld.parsed)

    @patch("lib.packet.opaque_field.HopOpaqueField.parse")
    def test_raw(self, parse):
        hop_op_fld = HopOpaqueField("data")
        parse.assert_called_once_with("data")


class TestHopOpaqueFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.parse
    """
    def test_basic(self):
        hop_op_fld = HopOpaqueField()
        data = bytes.fromhex('0e 2a 0a 0b 0c') + b'\x01'*3
        hop_op_fld.parse(data)
        ntools.eq_(hop_op_fld.info, 0x0e)
        ntools.eq_(hop_op_fld.exp_time, 0x2a)
        ntools.eq_(hop_op_fld.ingress_if, 0x0a0)
        ntools.eq_(hop_op_fld.egress_if, 0xb0c)
        ntools.eq_(hop_op_fld.mac, b'\x01'*3)
        ntools.assert_true(hop_op_fld.parsed)

    def test_len(self):
        hop_op_fld = HopOpaqueField()
        hop_op_fld.parse(bytes.fromhex('0e 2a 0a 0b 0c 0d 0e'))
        ntools.assert_false(hop_op_fld.parsed)
        ntools.eq_(hop_op_fld.info, 0)
        ntools.eq_(hop_op_fld.exp_time, 0)
        ntools.eq_(hop_op_fld.ingress_if, 0)
        ntools.eq_(hop_op_fld.egress_if, 0)
        ntools.eq_(hop_op_fld.mac, b'\x00'*3)


class TestHopOpaqueFieldFromValues(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.from_values
    """
    def test_basic(self):
        hop_op_fld = HopOpaqueField.from_values(42, 160, 2828, b'\x01'*3)
        ntools.eq_(hop_op_fld.exp_time, 42)
        ntools.eq_(hop_op_fld.ingress_if, 160)
        ntools.eq_(hop_op_fld.egress_if, 2828)
        ntools.eq_(hop_op_fld.mac, b'\x01'*3)

    def test_less_arg(self):
        hop_op_fld = HopOpaqueField.from_values(42)
        ntools.eq_(hop_op_fld.exp_time, 42)
        ntools.eq_(hop_op_fld.ingress_if, 0)
        ntools.eq_(hop_op_fld.egress_if, 0)
        ntools.eq_(hop_op_fld.mac, b'\x00'*3)               


class TestHopOpaqueFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.pack
    """
    def test_basic(self):
        hop_op_fld = HopOpaqueField()
        hop_op_fld.info = 0x0e
        hop_op_fld.exp_time = 0x2a
        hop_op_fld.ingress_if = 0x0a0
        hop_op_fld.egress_if = 0xb0c
        hop_op_fld.mac = b'\x01'*3
        data = bytes.fromhex('0e 2a 0a 0b 0c') + b'\x01'*3
        ntools.eq_(hop_op_fld.pack(), data)


class TestInforOpaqueFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.InfoOpaqueField.__init__
    """
    def test_basic(self):
        inf_op_fld = InfoOpaqueField()
        ntools.eq_(inf_op_fld.timestamp, 0)
        ntools.eq_(inf_op_fld.isd_id, 0)
        ntools.eq_(inf_op_fld.hops, 0)
        ntools.assert_false(inf_op_fld.up_flag)
        ntools.assert_false(inf_op_fld.parsed)

    @patch("lib.packet.opaque_field.InfoOpaqueField.parse")
    def test_raw(self, parse):
        inf_op_fld = InfoOpaqueField("data")
        parse.assert_called_once_with("data")


class TestInfoOpaqueFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.InfoOpaqueField.parse
    """
    def test_basic(self):
        inf_op_fld = InfoOpaqueField()
        inf_op_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))
        ntools.eq_(inf_op_fld.info, 0x0f>>1)
        ntools.eq_(inf_op_fld.timestamp, 0x2a0a0b0c)
        ntools.eq_(inf_op_fld.isd_id, 0x0d0e)
        ntools.eq_(inf_op_fld.hops, 0x0f)
        ntools.eq_(inf_op_fld.up_flag, 0x0f & 0x01)
        ntools.assert_true(inf_op_fld.parsed)

    def test_len(self):
        inf_op_fld = InfoOpaqueField()
        inf_op_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e'))
        ntools.eq_(inf_op_fld.info, 0)
        ntools.eq_(inf_op_fld.timestamp, 0)
        ntools.eq_(inf_op_fld.isd_id, 0)
        ntools.eq_(inf_op_fld.hops, 0)
        ntools.assert_false(inf_op_fld.up_flag)
        ntools.assert_false(inf_op_fld.parsed)


class TestInfoOpaqueFieldFromValues(object):
    """
    Unit tests for lib.packet.opaque_field.InfoOpaqueField.from_values
    """
    def test_basic(self):
        inf_op_fld = InfoOpaqueField.from_values(7, True, 705301260, 3342, 15)
        ntools.eq_(inf_op_fld.info, 7)
        ntools.eq_(inf_op_fld.timestamp, 705301260)
        ntools.eq_(inf_op_fld.isd_id, 3342)
        ntools.eq_(inf_op_fld.hops, 15)
        ntools.assert_true(inf_op_fld.up_flag)

    def test_less_arg(self):
        inf_op_fld = InfoOpaqueField.from_values()
        ntools.eq_(inf_op_fld.info, 0)
        ntools.eq_(inf_op_fld.timestamp, 0)
        ntools.eq_(inf_op_fld.isd_id, 0)
        ntools.eq_(inf_op_fld.hops, 0)
        ntools.assert_false(inf_op_fld.up_flag)               


class TestInfoOpaqueFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.InfoOpaqueField.pack
    """
    def test_basic(self):
        inf_op_fld = InfoOpaqueField()
        inf_op_fld.info = 0x0f>>1
        inf_op_fld.timestamp = 0x2a0a0b0c
        inf_op_fld.isd_id = 0x0d0e
        inf_op_fld.hops = 0x0f
        inf_op_fld.up_flag = 0x0f & 0x01
        ntools.eq_(inf_op_fld.pack(),bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))


class TestTRCFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.TRCField.__init__
    """
    def test_basic(self):
        trc_fld = TRCField()
        ntools.eq_(trc_fld.info, OpaqueFieldType.TRC_OF)
        ntools.eq_(trc_fld.trc_version, 0)
        ntools.eq_(trc_fld.if_id, 0)
        ntools.eq_(trc_fld.reserved, 0)
        ntools.assert_false(trc_fld.parsed)

    @patch("lib.packet.opaque_field.TRCField.parse")
    def test_raw(self, parse):
        trc_fld = TRCField("data")
        parse.assert_called_once_with("data")


class TestTRCFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.TRCField.parse
    """
    def test_basic(self):
        trc_fld = TRCField()
        trc_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))
        ntools.eq_(trc_fld.info, 0x0f)
        ntools.eq_(trc_fld.trc_version, 0x2a0a0b0c)
        ntools.eq_(trc_fld.if_id, 0x0d0e)
        ntools.eq_(trc_fld.reserved, 0x0f)
        ntools.assert_true(trc_fld.parsed)

    def test_len(self):
        trc_fld = TRCField()
        trc_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e'))
        ntools.eq_(trc_fld.info, OpaqueFieldType.TRC_OF)
        ntools.eq_(trc_fld.trc_version, 0)
        ntools.eq_(trc_fld.if_id, 0)
        ntools.eq_(trc_fld.reserved, 0)
        ntools.assert_false(trc_fld.parsed)


class TestTRCFieldFromValues(object):
    """
    Unit tests for lib.packet.opaque_field.TRCField.from_values
    """
    def test_basic(self):
        trc_fld = TRCField.from_values(705301260, 3342, 15)
        ntools.eq_(trc_fld.trc_version, 705301260)
        ntools.eq_(trc_fld.if_id, 3342)
        ntools.eq_(trc_fld.reserved, 15)

    def test_less_arg(self):
        trc_fld = TRCField.from_values()
        ntools.eq_(trc_fld.trc_version, 0)
        ntools.eq_(trc_fld.if_id, 0)
        ntools.eq_(trc_fld.reserved, 0)


class TestTRCFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.TRCField.pack
    """
    def test_basic(self):
        trc_fld = TRCField()
        trc_fld.info = 0x0f
        trc_fld.trc_version = 0x2a0a0b0c
        trc_fld.if_id = 0x0d0e
        trc_fld.reserved = 0x0f
        ntools.eq_(trc_fld.pack(),bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))
