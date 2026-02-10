import { GlobalId } from "./globalid";
import { utf8ArrayToString, stringToUtf8Array } from "./util";
import { Logger } from "./logger";

export class ByteStream {
  payload: number[];
  bitoffset: number;
  offset: number;
  constructor(payload: number[]) {
    this.payload = payload;
    this.bitoffset = 0;
    this.offset = 0;
  }

  readInt(): number {
    this.bitoffset = 0;
    let result =
      ((this.payload[this.offset] << 24) >>> 0) |
      (this.payload[this.offset + 1] << 16) |
      (this.payload[this.offset + 2] << 8) |
      this.payload[this.offset + 3];
    this.offset += 4;
    return result;
  }

  readByte(): number {
    this.bitoffset = 0;
    let result = this.payload[this.offset];
    this.offset++;
    return result;
  }

  readShort(): number {
    this.bitoffset = 0;
    let result =
      (this.payload[this.offset] << 8) | this.payload[this.offset + 1];
    this.offset += 2;
    return result;
  }

  readLong(): number {
    this.bitoffset = 0;
    let high = this.readInt();
    let low = this.readInt();
    return Number((BigInt(high) << 32n) | BigInt(low >>> 0));
  }

  readString(): string {
    this.bitoffset = 0;
    const length = this.readInt();
    if (length < 0 || length > 10000) {
      Logger.error("Invalid string length");
      throw Error();
    }
    const bytes = this.payload.slice(this.offset, this.offset + length);
    this.offset += length;
    return utf8ArrayToString(new Uint8Array(bytes));
  }

  writeDataReference(val: number) {
    this.bitoffset = 0;
    let classId = GlobalId.getClassId(val);
    let instanceId = GlobalId.getInstanceId(val);

    this.writeVInt(classId);
    if (classId > 0) this.writeVInt(instanceId);
  }

  readVInt(): number {
    let start = this.offset;
    this.bitoffset = 0;
    let b0 = this.payload[start];
    this.offset = start + 1;
    let result = b0 & 0x3f;
    if (b0 & 0x40) {
      if (b0 & 0x80) {
        let b1 = this.payload[start + 1];
        result = result | ((b1 & 0x7f) << 6);
        this.offset = start + 2;
        if (b1 & 0x80) {
          let b2 = this.payload[start + 2];
          result = result | ((b2 & 0x7f) << 13);
          this.offset = start + 3;
          if (b2 & 0x80) {
            let b3 = this.payload[start + 3];
            result = result | ((b3 & 0x7f) << 20);
            this.offset = start + 4;
            if (b3 & 0x80) {
              let b4 = this.payload[start + 4];
              this.offset = start + 5;
              result = result | (b4 << 27);
            }
          }
        }
      }
      result = -(result | (0xffffffc0 << ((this.offset - start - 1) * 7 - 6)));
    } else if (b0 & 0x80) {
      let b1 = this.payload[start + 1];
      result = result | ((b1 & 0x7f) << 6);
      this.offset = start + 2;
      if (b1 & 0x80) {
        let b2 = this.payload[start + 2];
        result = result | ((b2 & 0x7f) << 13);
        this.offset = start + 3;
        if (b2 & 0x80) {
          let b3 = this.payload[start + 3];
          result = result | ((b3 & 0x7f) << 20);
          this.offset = start + 4;
          if (b3 & 0x80) {
            let b4 = this.payload[start + 4];
            this.offset = start + 5;
            result = result | (b4 << 27);
          }
        }
      }
    }
    return result;
  }

  readVLong(): number {
    let high = this.readVInt();
    let low = this.readVInt();
    return Number((BigInt(high) << 32n) | BigInt(low >>> 0));
  }

  readBoolean(): boolean {
    this.bitoffset = 0;
    return this.payload[this.offset++] !== 0;
  }

  readDataReference(): number {
    const classId = this.readVInt();
    if (classId === 0) {
      return 0;
    }
    const instanceId = this.readVInt();
    return GlobalId.createGlobalId(classId, instanceId);
  }

  writeByte(value: number) {
    this.bitoffset = 0;
    this.payload.push(value & 0xff);
    this.offset++;
  }

  writeShort(value: number) {
    this.bitoffset = 0;
    this.payload.push((value >> 8) & 0xff);
    this.payload.push(value & 0xff);
    this.offset += 2;
  }

  writeInt(value: number) {
    this.bitoffset = 0;
    this.payload.push((value >> 24) & 0xff);
    this.payload.push((value >> 16) & 0xff);
    this.payload.push((value >> 8) & 0xff);
    this.payload.push(value & 0xff);
    this.offset += 4;
  }

  writeString(str: string) {
    this.bitoffset = 0;
    let bytes = stringToUtf8Array(str);
    this.writeInt(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      this.writeByte(bytes[i]);
    }
  }

  writeVInt(value: number) {
    this.bitoffset = 0;
    let temp = (value >> 25) & 0x40;
    let flipped = value ^ (value >> 31);

    temp |= value & 0x3f;
    value >>= 6;

    if ((flipped >>= 6) == 0) {
      this.writeByte(temp);
      return;
    }

    this.writeByte(temp | 0x80);

    do {
      this.writeByte((value & 0x7f) | ((flipped >>= 7) != 0 ? 0x80 : 0));
      value >>= 7;
    } while (flipped != 0);
  }

  writeVLong(high: number, low: number) {
    this.bitoffset = 0;
    this.writeVInt(high);
    this.writeVInt(low);
  }

  writeBoolean(value: boolean) {
    if (this.bitoffset == 0) {
      this.payload.push(0);
      this.offset++;
    }
    if (value) {
      this.payload[this.offset - 1] |= 1 << (this.bitoffset & 7);
    }
    this.bitoffset = (this.bitoffset + 1) & 7;
  }

  writeLong(high: number, low: number) {
    this.bitoffset = 0;
    this.writeInt(high);
    this.writeInt(low);
  }

  writeHex(hex: string): void {
    this.bitoffset = 0;

    hex = hex.replace(/[\s-]/g, "");

    if (hex.length % 2 != 0) {
      Logger.error("Invalid hex length");
      throw new Error();
    }

    for (let i = 0; i < hex.length; i += 2) {
      const byteStr = hex.substring(i, i + 2);
      const byte = parseInt(byteStr, 16);

      if (isNaN(byte)) {
        Logger.error("Invalid hex length", byte);
        throw new Error();
      }

      this.writeByte(byte);
    }
  }

  writeBytes(value: number[], length: number) {
    this.writeInt(length);
    for (let i = 0; i < length; i++) {
      this.payload[this.offset + i] = value[i] & 0xff;
    }
    this.offset += length;
  }
}
