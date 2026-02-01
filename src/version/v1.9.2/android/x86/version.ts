import { create } from "domain";
import { ByteStream } from "src/bytestream";
import { createMessageByType } from "src/definitions";

export const version = {
  gmv: "1.9.2",
  platform: "android",
  architecture: "x86",
  offsets: {
    ServerConnectionUpdate: 0xc00c6,
    CreateMessageByType: 0x278438,
    OperatorNew: 0x615ab0,
    ReceiveMessage: 0xb9034,
    MessageManagerInstance: 0x8ada3c,
    Send: 0x2e2640,
    SendMessage: 0xb8e2a,

    DebuggerError: 0x3abfb0,
    DebuggerWarning: 0x3abbd0,

    ServerConnectionMessaging: 4,
    Connection: 64,
    State: 4,
    HasConnectFailed: 104,

    Messaging: 4,

    GetMessageType: 20,
    Destruct: 24,
    Encode: 8,
    Decode: 12,

    ByteStream: 8,
    Version: 4,

    PayloadPtr: 28,
    PayloadSize: 20,
    PayloadOffset: 16,

    CreateMessageByTypeCMP: 0x278455,
    CreateMessageByTypeJumpAddress: 0x278499,

    StringConstructor: 0x2e98f0,

    GetCSV: 0x332cf0,
    GetTable: 0x3a6650,
    GetColumnCount: 0x3a79e0,
    GetColumnIndexByName: 0x3a7df0,
    GetRowCount: 0x3a8330,
    GetRowAt: 0x3a8080,
    GetRowName: 0x3a6ff0,
    GetBooleanValueAt: 0x3a7110,
    GetIntegerValueAt: 0x3a7160,

    AAssetManagerOpen: 0x5a140,

    SendKeepAliveMessage: 0xbe056,
    ShowBadConnection: 0xa8fe2,
  },
};
