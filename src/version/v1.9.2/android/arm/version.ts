import { create } from "domain";
import { ByteStream } from "src/bytestream";
import { createMessageByType } from "src/definitions";

export const version = {
  gmv: "1.9.2",
  platform: "android",
  architecture: "arm",
  offsets: {
    ServerConnectionUpdate: 0x9e615,
    CreateMessageByType: 0x1c011d,
    OperatorNew: 0x3d1bc9,
    ReceiveMessage: 0x996dd,
    MessageManagerInstance: 0x59ca60,
    Send: 0x1fafb1,
    SendMessage: 0x99561,

    DebuggerError: 0x261181,
    DebuggerWarning: 0x260f3d,

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

    CreateMessageByTypeLDRB: 0x1c0120,
    CreateMessageByTypeJumpAddress: 0x1c0146,

    StringConstructor: 0x1feb71,

    GetCSV: 0x227c19,
    GetTable: 0x25e329,
    GetColumnCount: 0x25ece9,
    GetColumnIndexByName: 0x25eedd,
    GetRowCount: 0x25f179,
    GetRowAt: 0x25f01d,
    GetRowName: 0x25e7c1,
    GetValueAt: 0x25ee40,
    GetBooleanValueAt: 0x25e845,
    GetIntegerValueAt: 0x25e875,

    AAssetManagerOpen: 0x5ad1c,

    SendKeepAliveMessage: 0x9d01c,
    ShowBadConnection: 0x8eb38,
  },
};
