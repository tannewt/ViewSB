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
        return "tag {} to lun #{}".format(self.tag, self.lun)

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
        return "tag {} reply {}".format(self.tag, self.status)

class MSCTransaction(ViewSBDecoder):
    """
    Decoder that converts transactions into more-specific types of transactions.
    """

    INCLUDE_IN_ALL = True

    def can_handle_packet(self, packet):
        return type(packet) is USBTransaction and (
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

    def can_handle_packet(self, packet):
        if isinstance(packet, (CommandBlockWrapper, CommandStatusWrapper)):
            return True
        if self.tag:
            return True
        return False


    def consume_packet(self, packet):
        print("parse", packet)

        #self.emit_packet(packet)