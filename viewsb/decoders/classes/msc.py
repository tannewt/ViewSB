from ...decoder import ViewSBDecoder
from ...packet import USBTransaction, USBTransfer

import struct

class CommandBlockWrapper(USBTransfer):
    signature = b"\x55\x53\x42\x43"

    FIELDS = {'tag', 'data_transfer_length', 'flags', 'lun'}

    @classmethod
    def from_transaction(cls, transaction):

        fields = transaction.__dict__.copy()
        fields["subordinate_packets"] = [transaction]
        fields["tag"], fields["data_transfer_length"], fields["flags"], fields["lun"], command_block_length = struct.unpack_from("<IIBBB", fields["data"], offset=4)

        fields["data"] = fields["data"][15:15+command_block_length]
        return cls(**fields)


    def summarize(self):
        return "tag {} to lun #{} with length {}".format(self.tag, self.lun, self.data_transfer_length)

STATUS = ["passed", "failed", "phase error"]

class CommandStatusWrapper(USBTransfer):
    signature = b"\x55\x53\x42\x53"

    FIELDS = {'tag', 'data_residue', 'status'}

    @classmethod
    def from_transaction(cls, transaction):

        fields = transaction.__dict__.copy()
        fields["subordinate_packets"] = [transaction]
        fields["tag"], fields["data_residue"], fields["status"] = struct.unpack_from("<IIB", fields["data"], offset=4)
        fields["data"] = None
        return cls(**fields)


    def summarize(self):
        return "tag {} reply {}".format(self.tag, STATUS[self.status])

class SCSICommand(USBTransfer):
    @classmethod
    def from_subordinates(cls, subordinates):
        fields = subordinates[0].__dict__.copy()
        fields["subordinate_packets"] = subordinates
        fields["data"] = None
        return cls(**fields)

    def summarize(self):
        return "unknown scsi command"

class TestUnitReady(SCSICommand):
    opcode = 0x00

    FIELDS = {'control'}
    @classmethod
    def from_subordinates(cls, subordinates):
        fields = subordinates[0].__dict__.copy()
        fields["subordinate_packets"] = subordinates
        fields['control'] = subordinates[0].data[5]

        fields["data"] = None
        return cls(**fields)


    def summarize(self):
        return str(self.control)

SENSE_KEY = ["NO SENSE", "RECOVERED ERROR", "NOT READY", "MEDIUM ERROR", "HARDWARE ERROR", "ILLEGAL REQUEST", "UNIT ATTENTION", "DATA PROTECT", "BLANK CHECK", "VENDOR SPECIFIC", "COPY ABORTED", "ABORTED COMMAND", "Reserved", "VOLUME OVERFLOW", "MISCOMPARE", "COMPLETED"]

ADDITIONAL_SENSE = {
    (4, 0): "Logical Unit Not Ready, Cause Not Reportable",
    (0x3a, 0): "Media Not Present"
}
class RequestSense(SCSICommand):
    opcode = 0x03

    FIELDS = {'descriptor_format', 'allocation_length', 'control', 'response_code', 'sense_key', 'additional_sense_code', 'additional_sense_code_qualifier'}
    @classmethod
    def from_subordinates(cls, subordinates):
        fields = subordinates[0].__dict__.copy()
        fields["subordinate_packets"] = subordinates
        fields['descriptor_length'] = subordinates[0].data[1] & 0b1
        fields['allocation_length'] = subordinates[0].data[4]
        fields['control'] = subordinates[0].data[5]

        data = subordinates[1].data[:fields['allocation_length']]
        fields["data"] = data
        response_code = data[0] & 0x7f
        fields["response_code"] = response_code
        if response_code in (0x70, 0x71):
            fields['sense_key'] = data[2] & 0xf
            fields['additional_sense_code'] = data[12]
            fields['additional_sense_code_qualifier'] = data[13]
        else:
            fields['sense_key'] = data[1] & 0xf
            fields['additional_sense_code'] = data[2]
            fields['additional_sense_code_qualifier'] = data[3]

        return cls(**fields)

    def summarize(self):
        additional_sense_key = (self.additional_sense_code, self.additional_sense_code_qualifier)
        if additional_sense_key in ADDITIONAL_SENSE:
            additional_sense = ADDITIONAL_SENSE[additional_sense_key]
        else:
            additional_sense = "({:02x}, {:02x})".format(*additional_sense_key)
        return SENSE_KEY[self.sense_key] + " " + additional_sense

class Inquiry(SCSICommand):
    opcode = 0x12

    FIELDS = {'descriptor_format', 'allocation_length', 'control', 'response_code', 'sense_key', 'additional_sense_code', 'additional_sense_code_qualifier'}
    @classmethod
    def from_subordinates(cls, subordinates):
        fields = subordinates[0].__dict__.copy()
        fields["subordinate_packets"] = subordinates
        fields['descriptor_length'] = subordinates[0].data[1] & 0b1
        fields['allocation_length'] = subordinates[0].data[4]
        fields['control'] = subordinates[0].data[5]

        data = subordinates[1].data[:fields['allocation_length']]
        fields["data"] = data
        response_code = data[0] & 0x7f
        fields["response_code"] = response_code
        if response_code in (0x70, 0x71):
            fields['sense_key'] = data[2] & 0xf
            fields['additional_sense_code'] = data[12]
            fields['additional_sense_code_qualifier'] = data[13]
        else:
            fields['sense_key'] = data[1] & 0xf
            fields['additional_sense_code'] = data[2]
            fields['additional_sense_code_qualifier'] = data[3]

        return cls(**fields)

    def summarize(self):
        additional_sense_key = (self.additional_sense_code, self.additional_sense_code_qualifier)
        if additional_sense_key in ADDITIONAL_SENSE:
            additional_sense = ADDITIONAL_SENSE[additional_sense_key]
        else:
            additional_sense = "({:02x}, {:02x})".format(*additional_sense_key)
        return SENSE_KEY[self.sense_key] + " " + additional_sense

class PreventAllowMediumRemoval(SCSICommand):
    opcode = 0x1e

    FIELDS = {'descriptor_format', 'allocation_length', 'control', 'response_code', 'sense_key', 'additional_sense_code', 'additional_sense_code_qualifier'}
    @classmethod
    def from_subordinates(cls, subordinates):
        fields = subordinates[0].__dict__.copy()
        fields["subordinate_packets"] = subordinates
        fields['descriptor_length'] = subordinates[0].data[1] & 0b1
        fields['allocation_length'] = subordinates[0].data[4]
        fields['control'] = subordinates[0].data[5]

        return cls(**fields)

    def summarize(self):
        return "not implemented"

class ReadCapacity10(SCSICommand):
    opcode = 0x25

    FIELDS = {'descriptor_format', 'allocation_length', 'control', 'response_code', 'sense_key', 'additional_sense_code', 'additional_sense_code_qualifier'}
    @classmethod
    def from_subordinates(cls, subordinates):
        fields = subordinates[0].__dict__.copy()
        fields["subordinate_packets"] = subordinates
        fields['descriptor_length'] = subordinates[0].data[1] & 0b1
        fields['allocation_length'] = subordinates[0].data[4]
        fields['control'] = subordinates[0].data[5]

        return cls(**fields)

    def summarize(self):
        return "not implemented"

class ModeSense6(SCSICommand):
    opcode = 0x1a

    FIELDS = {'descriptor_format', 'allocation_length', 'control', 'response_code', 'sense_key', 'additional_sense_code', 'additional_sense_code_qualifier'}
    @classmethod
    def from_subordinates(cls, subordinates):
        fields = subordinates[0].__dict__.copy()
        fields["subordinate_packets"] = subordinates
        fields['descriptor_length'] = subordinates[0].data[1] & 0b1
        fields['allocation_length'] = subordinates[0].data[4]
        fields['control'] = subordinates[0].data[5]

        return cls(**fields)

    def summarize(self):
        return "not implemented"

class Read10(SCSICommand):
    opcode = 0x28

    FIELDS = {'descriptor_format', 'allocation_length', 'control', 'response_code', 'sense_key', 'additional_sense_code', 'additional_sense_code_qualifier'}
    @classmethod
    def from_subordinates(cls, subordinates):
        fields = subordinates[0].__dict__.copy()
        fields["subordinate_packets"] = subordinates
        fields['descriptor_length'] = subordinates[0].data[1] & 0b1
        fields['allocation_length'] = subordinates[0].data[4]
        fields['control'] = subordinates[0].data[5]

        return cls(**fields)

    def summarize(self):
        return "not implemented"

class StartStopUnit(SCSICommand):
    opcode = 0x1b

    FIELDS = {'immediate', 'power_condition_modifier', 'power_condition', 'no_flush', 'load_eject', 'start', 'control'}

    @classmethod
    def from_subordinates(cls, subordinates):
        fields = subordinates[0].__dict__.copy()
        fields["subordinate_packets"] = subordinates
        fields['immediate'] = subordinates[0].data[1] & 1 != 0
        fields['power_condition_modifier'] = subordinates[0].data[3] & 0xf
        fields['power_condition'] = (subordinates[0].data[4] & 0xf0) >> 4

        fields['no_flush'] = subordinates[0].data[4] & 0b100 != 0
        fields['load_eject'] = subordinates[0].data[4] & 0b10 != 0
        fields['start'] = subordinates[0].data[4] & 0b1 != 0

        fields["data"] = None
        return cls(**fields)

    def summarize(self):
        if self.power_condition_modifier == 0:
            if self.power_condition == 0:
                bits = []
                for bit in ["load_eject", "start"]:
                    if getattr(self, bit, False):
                        bits.append(bit)
                return "start valid: " + " ".join(bits)

class MSCTransaction(ViewSBDecoder):
    """
    Decoder that converts transactions into more-specific types of transactions.
    """

    INCLUDE_IN_ALL = True

    def can_handle_packet(self, packet):
        return type(packet) is USBTransaction and packet.data and (
            packet.data.startswith(CommandBlockWrapper.signature) or packet.data.startswith(CommandStatusWrapper.signature))


    def consume_packet(self, packet):
        new_packet = None
        if packet.data.startswith(CommandBlockWrapper.signature):
            new_packet = CommandBlockWrapper.from_transaction(packet)
        elif packet.data.startswith(CommandStatusWrapper.signature):
            new_packet = CommandStatusWrapper.from_transaction(packet)

        if new_packet:
            self.emit_packet(new_packet)
        else:
            print("dropping", packet)

class SCSITransaction(ViewSBDecoder):
    """
    Decoder that converts transactions into more-specific types of transactions.
    """

    INCLUDE_IN_ALL = True

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.tag = None
        self.subordinates = []

        self.opcode_map = {}
        for cls in [TestUnitReady, RequestSense, StartStopUnit, Inquiry, PreventAllowMediumRemoval, ReadCapacity10, ModeSense6, Read10]:
            self.opcode_map[cls.opcode] = cls

    def can_handle_packet(self, packet):
        if isinstance(packet, (CommandBlockWrapper, CommandStatusWrapper)):
            return True
        if self.tag and isinstance(packet, USBTransaction):
            return True
        return False


    def consume_packet(self, packet):
        if isinstance(packet, CommandBlockWrapper):
            self.tag = packet.tag
        elif isinstance(packet, CommandStatusWrapper):
            if self.tag != packet.tag:
                pass
                # handle this because it is an error.
            self.subordinates.append(packet)
            opcode = self.subordinates[0].data[0]
            packet = self.opcode_map[opcode].from_subordinates(self.subordinates)
            self.emit_packet(packet)
            self.subordinates = []
            self.tag = None

        if self.tag is not None:
            self.subordinates.append(packet)

        #self.emit_packet(packet)
