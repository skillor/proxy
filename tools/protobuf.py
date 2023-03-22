import struct


class Protobuf:
    @staticmethod
    def get_dynamic_wire_format(data, start, end):
        wire_type = data[start] & 0x7
        first_byte = data[start]
        if (first_byte & 0x80) == 0:
            field_number = (first_byte >> 3)
            return start + 1, wire_type, field_number
        else:
            byte_list = []
            pos = 0
            while True:
                if start + pos >= end:
                    return None, None, None
                one_byte = data[start + pos]
                byte_list.append(one_byte & 0x7F)
                pos = pos + 1
                if one_byte & 0x80 == 0x0:
                    break

            new_start = start + pos

            index = len(byte_list) - 1
            field_number = 0
            while index >= 0:
                field_number = (field_number << 0x7) + byte_list[index]
                index = index - 1

            field_number = (field_number >> 3)
            return new_start, wire_type, field_number

    @staticmethod
    def retrieve_int(data, start, end):
        pos = 0
        byte_list = []
        while True:
            if start + pos >= end:
                return None, None, False
            one_byte = data[start + pos]
            byte_list.append(one_byte & 0x7F)
            pos = pos + 1
            if one_byte & 0x80 == 0x0:
                break

        new_start = start + pos

        index = len(byte_list) - 1
        num = 0
        while index >= 0:
            num = (num << 0x7) + byte_list[index]
            index = index - 1
        return num, new_start, True

    @staticmethod
    def parse_repeated_field(data, start, end, message):
        while start < end:
            (num, start, success) = Protobuf.retrieve_int(data, start, end)
            if not success:
                return False
            message.append(num)
        return True

    @staticmethod
    def parse_data(data, start, end, messages, depth=0):
        strings = []
        ordinary = 0
        while start < end:
            (start, wire_type, field_number) = Protobuf.get_dynamic_wire_format(data, start, end)
            if start is None:
                return False

            if wire_type == 0x00:  # Varint
                (num, start, success) = Protobuf.retrieve_int(data, start, end)
                if not success:
                    return False

                if depth != 0:
                    strings.append('\t' * depth)
                strings.append("(%d) Varint: %d\n" % (field_number, num))
                messages['%02d:%02d:Varint' % (field_number, ordinary)] = num
                ordinary = ordinary + 1

            elif wire_type == 0x01:  # 64-bit
                num = 0
                pos = 7
                while pos >= 0:
                    # if start+1+pos >= end:
                    if start + pos >= end:
                        return False
                    # num = (num << 8) + ord(data[start+1+pos])
                    num = (num << 8) + data[start + pos]
                    pos = pos - 1

                # start = start + 9
                start = start + 8
                try:
                    float_num = struct.unpack('d', struct.pack('q', int(hex(num), 16)))
                    float_num = float_num[0]
                except ValueError:
                    float_num = None

                if depth != 0:
                    strings.append('\t' * depth)
                if float_num is not None:
                    strings.append("(%d) 64-bit: 0x%x / %f\n" % (field_number, num, float_num))
                    messages['%02d:%02d:64-bit' % (field_number, ordinary)] = float_num
                else:
                    strings.append("(%d) 64-bit: 0x%x\n" % (field_number, num))
                    messages['%02d:%02d:64-bit' % (field_number, ordinary)] = num

                ordinary = ordinary + 1

            elif wire_type == 0x02:  # Length-delimited
                cur_str_index = len(strings)
                # (stringLen, start, success) = RetrieveInt(data, start+1, end)
                (stringLen, start, success) = Protobuf.retrieve_int(data, start, end)
                if not success:
                    return False
                # stringLen = ord(data[start+1])
                if depth != 0:
                    strings.append('\t' * depth)
                strings.append("(%d) embedded message:\n" % field_number)
                messages['%02d:%02d:embedded message' % (field_number, ordinary)] = {}
                if start + stringLen > end:
                    del strings[cur_str_index + 1:]  # pop failed result
                    messages.pop('%02d:%02d:embedded message' % (field_number, ordinary), None)
                    return False

                ret = Protobuf.parse_data(data, start, start + stringLen,
                                          messages['%02d:%02d:embedded message' % (field_number, ordinary)], depth + 1)
                # print '%d:%d:embedded message' % (field_number, ordinary)
                if not ret:
                    del strings[cur_str_index + 1:]  # pop failed result
                    # print 'pop: %d:%d:embedded message' % (field_number, ordinary)
                    messages.pop('%02d:%02d:embedded message' % (field_number, ordinary), None)
                    # print messages
                    if depth != 0:
                        strings.append('\t' * depth)

                    strings.append("(%d) repeated:\n" % field_number)
                    try:
                        data[start:start + stringLen].decode('utf-8')  # .encode('utf-8')
                        strings.append("(%d) string: %s\n" % (field_number, data[start:start + stringLen]))
                        messages[
                            '%02d:%02d:string' % (field_number, ordinary)
                        ] = data[start:start + stringLen].decode('utf-8')
                    except UnicodeDecodeError:
                        if depth != 0:
                            strings.append('\t' * depth)

                        strings.append("(%d) repeated:\n" % field_number)
                        messages['%02d:%02d:repeated' % (field_number, ordinary)] = []
                        ret = Protobuf.parse_repeated_field(data, start, start + stringLen,
                                                            messages['%02d:%02d:repeated' % (field_number, ordinary)])
                        if not ret:
                            del strings[cur_str_index + 1:]  # pop failed result
                            messages.pop('%02d:%02d:repeated' % (field_number, ordinary), None)
                            # print traceback.format_exc()
                            hex_str = ['0x%x' % x for x in data[start:start + stringLen]]
                            hex_str = ':'.join(hex_str)
                            strings.append("(%d) bytes: %s\n" % (field_number, hex_str))
                            messages['%02d:%02d:bytes' % (field_number, ordinary)] = hex_str

                ordinary = ordinary + 1
                # start = start+2+stringLen
                start = start + stringLen

            elif wire_type == 0x05:  # 32-bit
                num = 0
                pos = 3
                while pos >= 0:

                    # if start+1+pos >= end:
                    if start + pos >= end:
                        return False
                    # num = (num << 8) + ord(data[start+1+pos])
                    num = (num << 8) + data[start + pos]
                    pos = pos - 1

                # start = start + 5
                start = start + 4
                try:
                    float_num = struct.unpack('f', struct.pack('i', int(hex(num), 16)))
                    float_num = float_num[0]
                except (ValueError, struct.error):
                    float_num = None

                if depth != 0:
                    strings.append('\t' * depth)
                if float_num is not None:
                    strings.append("(%d) 32-bit: 0x%x / %f\n" % (field_number, num, float_num))
                    messages['%02d:%02d:32-bit' % (field_number, ordinary)] = float_num
                else:
                    strings.append("(%d) 32-bit: 0x%x\n" % (field_number, num))
                    messages['%02d:%02d:32-bit' % (field_number, ordinary)] = num

                ordinary = ordinary + 1

            else:
                return False

        return True

    @staticmethod
    def gen_value_list(value):
        value_list = []
        # while value > 0:
        while value >= 0:
            one_byte = (value & 0x7F)
            value = (value >> 0x7)
            if value > 0:
                one_byte |= 0x80
            value_list.append(one_byte)
            if value == 0:
                break

        return value_list

    @staticmethod
    def write_value(value, output):
        byte_written = 0
        # while value > 0:
        while value >= 0:
            one_byte = (value & 0x7F)
            value = (value >> 0x7)
            if value > 0:
                one_byte |= 0x80
            output.append(one_byte)
            byte_written += 1
            if value == 0:
                break

        return byte_written

    @staticmethod
    def write_varint(field_number, value, output):
        byte_written = 0
        wire_format = (field_number << 3) | 0x00
        byte_written += Protobuf.write_value(wire_format, output)
        while value >= 0:
            one_byte = (value & 0x7F)
            value = (value >> 0x7)
            if value > 0:
                one_byte |= 0x80
            output.append(one_byte)
            byte_written += 1
            if value == 0:
                break

        return byte_written

    @staticmethod
    def write_64bit_float(field_number, value, output):
        byte_written = 0
        wire_format = (field_number << 3) | 0x01
        byte_written += Protobuf.write_value(wire_format, output)

        bytes_str = struct.pack('d', value).hex()
        n = 2
        bytes_list = [bytes_str[i:i + n] for i in range(0, len(bytes_str), n)]
        # i = len(bytesList) - 1
        # while i >= 0:
        #    output.append(int(bytesList[i],16))
        #    byteWritten += 1
        #    i -= 1
        for i in range(0, len(bytes_list)):
            output.append(int(bytes_list[i], 16))
            byte_written += 1

        return byte_written

    @staticmethod
    def write_64bit(field_number, value, output):
        byte_written = 0
        wire_format = (field_number << 3) | 0x01
        byte_written += Protobuf.write_value(wire_format, output)

        for i in range(0, 8):
            output.append(value & 0xFF)
            value = (value >> 8)
            byte_written += 1

        return byte_written

    @staticmethod
    def write_32bit_float(field_number, value, output):
        byte_written = 0
        wire_format = (field_number << 3) | 0x05
        # output.append(wireFormat)
        # byteWritten += 1
        byte_written += Protobuf.write_value(wire_format, output)

        bytes_str = struct.pack('f', value).hex()
        n = 2
        bytes_list = [bytes_str[i:i + n] for i in range(0, len(bytes_str), n)]
        # i = len(bytesList) - 1
        # while i >= 0:
        #    output.append(int(bytesList[i],16))
        #    byteWritten += 1
        #    i -= 1
        for i in range(0, len(bytes_list)):
            output.append(int(bytes_list[i], 16))
            byte_written += 1

        return byte_written

    @staticmethod
    def write_32bit(field_number, value, output):
        byte_written = 0
        wire_format = (field_number << 3) | 0x05
        # output.append(wireFormat)
        # byteWritten += 1
        byte_written += Protobuf.write_value(wire_format, output)

        for i in range(0, 4):
            output.append(value & 0xFF)
            value = (value >> 8)
            byte_written += 1

        return byte_written

    @staticmethod
    def write_repeated_field(message, output):
        byte_written = 0
        for v in message:
            byte_written += Protobuf.write_value(v, output)
        return byte_written

    @staticmethod
    def decode(binary):
        messages = {}
        ret = Protobuf.parse_data(binary, 0, len(binary), messages)

        if not ret:
            return False

        return messages

    @staticmethod
    def encode(messages, output):
        byte_written = 0
        for key in sorted(messages, key=lambda x: int(x.split(':')[1])):
            key_list = key.split(':')
            field_number = int(key_list[0])
            wire_type = key_list[2]
            value = messages[key]

            if wire_type == 'Varint':
                byte_written += Protobuf.write_varint(field_number, value, output)
            elif wire_type == '32-bit':
                if isinstance(value, float):
                    byte_written += Protobuf.write_32bit_float(field_number, value, output)
                else:
                    byte_written += Protobuf.write_32bit(field_number, value, output)
            elif wire_type == '64-bit':
                if isinstance(value, float):
                    byte_written += Protobuf.write_64bit_float(field_number, value, output)
                else:
                    byte_written += Protobuf.write_64bit(field_number, value, output)
            elif wire_type == 'embedded message':
                wire_format = (field_number << 3) | 0x02
                byte_written += Protobuf.write_value(wire_format, output)
                index = len(output)
                tmp_byte_written = Protobuf.encode(messages[key], output)
                value_list = Protobuf.gen_value_list(tmp_byte_written)
                list_len = len(value_list)
                for i in range(0, list_len):
                    output.insert(index, value_list[i])
                    index += 1
                # output[index] = tmpByteWritten
                # print "output:", output
                byte_written += tmp_byte_written + list_len
            elif wire_type == 'repeated':
                wire_format = (field_number << 3) | 0x02
                byte_written += Protobuf.write_value(wire_format, output)
                index = len(output)
                tmp_byte_written = Protobuf.write_repeated_field(messages[key], output)
                value_list = Protobuf.gen_value_list(tmp_byte_written)
                list_len = len(value_list)
                for i in range(0, list_len):
                    output.insert(index, value_list[i])
                    index += 1
                # output[index] = tmpByteWritten
                # print "output:", output
                byte_written += tmp_byte_written + list_len
            elif wire_type == 'string':
                wire_format = (field_number << 3) | 0x02
                byte_written += Protobuf.write_value(wire_format, output)

                bytes_str = [elem for elem in messages[key].encode('utf-8')]

                byte_written += Protobuf.write_value(len(bytes_str), output)

                output.extend(bytes_str)
                byte_written += len(bytes_str)
            elif wire_type == 'bytes':
                wire_format = (field_number << 3) | 0x02
                byte_written += Protobuf.write_value(wire_format, output)

                bytes_str = [int(byte, 16) for byte in messages[key].split(':')]
                byte_written += Protobuf.write_value(len(bytes_str), output)

                output.extend(bytes_str)
                byte_written += len(bytes_str)

        return byte_written


def parse_protobuf(data):
    messages = {}
    Protobuf.parse_data(data, 0, len(data), messages)
    return messages


def serialize_protobuf(data):
    b = []
    Protobuf.encode(data, b)
    return bytes(b)
