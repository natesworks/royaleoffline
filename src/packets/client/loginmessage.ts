import { ByteStream } from "src/bytestream";
import { Messaging } from "src/messaging";
import { OwnHomeDataMessage } from "../server/ownhomedatamessage";
import { LoginOkMessage } from "../server/loginokmessage";
import { UserData } from "src/userdata";
import { userdata } from "src/definitions";
import { Logger } from "src/utility/logger";

export class LoginMessageData {}

export class LoginMessage {
  static decode(stream: ByteStream): LoginMessageData {
    return new LoginMessageData();
  }

  static execute(data: LoginMessageData) {
    userdata.read();
    Messaging.sendOfflineMessage(20104, LoginOkMessage.encode());
    Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode());
  }
}
