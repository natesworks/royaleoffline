import { GoHomeFromOfflinePracticeMessage } from "./packets/client/battle/gohomefromofflinepracticemessage";
import { AvatarNameCheckRequestMessage } from "./packets/client/home/avatarnamecheckrequestmessage";
import { ChangeAvatarNameMessage } from "./packets/client/home/changeavatarnamemessage";
import { EndClientTurnMessage } from "./packets/client/home/endclientturnmessage";
import { StartMissionMessage } from "./packets/client/home/startmissionmessage";
import { LoginMessage } from "./packets/client/login/loginmessage";
import { AvailableServerCommandMessage } from "./packets/server/home/availableservercommandmessage";
import { OwnHomeDataMessage } from "./packets/server/home/ownhomedatamessage";
import { LoginOkMessage } from "./packets/server/login/loginokmessage";
import { Logger } from "./utility/logger";

export class LogicScrollMessageFactory {
  static createMessageByType(type: number, messagePayload: number[]): any {
    switch (type) {
      case 10101:
        return new LoginMessage(messagePayload);
      case 10212:
        return new ChangeAvatarNameMessage(messagePayload);
      case 14104:
        return new StartMissionMessage(messagePayload);
      case 14101:
        return new GoHomeFromOfflinePracticeMessage(messagePayload);
      case 14102:
        return new EndClientTurnMessage(messagePayload);
      case 14600:
        return new AvatarNameCheckRequestMessage(messagePayload);
      case 20104:
        return new LoginOkMessage(messagePayload);
      case 24101:
        return new OwnHomeDataMessage(messagePayload);
      case 24111:
        return new AvailableServerCommandMessage(messagePayload);
      default:
        Logger.error(
          "LogicScrollMessageFactory::createMessageByType",
          "Unknown type",
          type,
        );
    }
  }
}
