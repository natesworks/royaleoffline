import { create } from "domain";
import { ByteStream } from "src/bytestream";
import { createMessageByType } from "src/definitions";

export const version = {
  gmv: "1.9.2",
  platform: "android",
  architecture: "arm",
  offsets: {
    ServerConnectionUpdate: 0x9e614,
    CreateMessageByType: 0x1c011c,
    OperatorNew: 0x3d1bc8,
    ReceiveMessage: 0x996dc,
    MessageManagerInstance: 0x59ca60,
    Send: 0x1fafb0,
    SendMessage: 0x99560,

    DebuggerError: 0x261180,
    DebuggerWarning: 0x260f3c,

    ServerConnectionMessaging: 4,
    Connection: 64,
    State: 4,
    HasConnectFailed: 104,

    GetMessageType: 20,
    Destruct: 24,
    Encode: 8,
    Decode: 12,

    ByteStream: 8,
    Version: 4,

    PayloadPtr: 28,
    PayloadSize: 20,
    PayloadOffset: 16,

    CreateMessageByTypeLDRB: 0x1c0120,
    CreateMessageByTypeJumpAddress: 0x1c0146,

    StringConstructor: 0x1feb70,

    GetCSV: 0x227c18,
    GetTable: 0x25e328,
    GetColumnCount: 0x25ece8,
    GetColumnIndexByName: 0x25eedc,
    GetRowCount: 0x25f178,
    GetRowAt: 0x25f01c,
    GetRowName: 0x25e7c0,
    GetBooleanValueAt: 0x25e844,
    GetIntegerValueAt: 0x25e874,

    AAssetManagerOpen: 0x5ad1c,
  },
};
