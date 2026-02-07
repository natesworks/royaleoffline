import { Offsets } from "./offsets.js";
import { PiranhaMessage } from "./piranhamessage.js";
import {
  addGameButton,
  base,
  loadAsset,
  startTrainingCampMatch,
} from "./definitions.js";
import { Messaging } from "./messaging.js";
import { ByteStream } from "./bytestream.js";
import { Logger } from "./utility/logger.js";
import { backtrace, createStringObject } from "./util.js";
import { create } from "domain";

export function installHooks() {
  Interceptor.attach(base.add(Offsets.DebuggerWarning), {
    onEnter(args) {
      let text = args[0].readUtf8String();
      Logger.warn(text);
    },
  });

  Interceptor.attach(base.add(Offsets.DebuggerError), {
    onEnter(args) {
      Logger.error(args[0].readUtf8String());
      Logger.debug("Backtrace:");
      backtrace(this.context);
    },
  });

  Interceptor.attach(base.add(Offsets.ServerConnectionUpdate), {
    onEnter(args) {
      let messaging = args[0]
        .add(Offsets.ServerConnectionMessaging)
        .readPointer();
      messaging.add(Offsets.HasConnectFailed).readU8();
      let connection = messaging.add(Offsets.Connection);
      connection.add(Offsets.State).writeU8(5);
    },
  });

  Memory.patchCode(
    base.add(Offsets.CreateMessageByTypeLDRB),
    Process.pageSize,
    (code) => {
      const pcWriter = new ThumbWriter(code);
      pcWriter.putBranchAddress(
        base.add(Offsets.CreateMessageByTypeJumpAddress),
      );
      pcWriter.flush();
    },
  );

  Interceptor.attach(base.add(Offsets.SendMessage), {
    onEnter(args) {
      PiranhaMessage.encode(args[1]);
      let messaging = args[0].add(Offsets.Messaging).readPointer();
      messaging.add(Offsets.State).writeInt(5);
    },
  });

  Interceptor.replace(
    base.add(Offsets.Send),
    new NativeCallback(
      function (_self, message) {
        let type = PiranhaMessage.getMessageType(message);
        let length = PiranhaMessage.getEncodingLength(message);

        Logger.info("Recieved message of type:", type);
        Logger.verbose("Length:", length);

        let payloadPtr = PiranhaMessage.getByteStream(message)
          .add(Offsets.PayloadPtr)
          .readPointer();
        let payload = payloadPtr.readByteArray(length);
        if (payload !== null && length > 0) {
          Logger.debug("Stream dump:", payload);
          Messaging.handleMessage(type, Array.from(new Uint8Array(payload)));
        } else {
          Messaging.handleMessage(type, []);
        }

        PiranhaMessage.destroyMessage(message);

        return 0;
      },
      "int",
      ["pointer", "pointer"],
    ),
  );

  Interceptor.replace(
    base.add(Offsets.SendKeepAliveMessage),
    new NativeCallback(function () {}, "void", []),
  );

  Interceptor.replace(
    base.add(Offsets.ShowBadConnection),
    new NativeCallback(function () {}, "void", []),
  );

  Interceptor.replace(
    base.add(Offsets.StartBattle),
    new NativeCallback(
      function (a1: NativePointer) {
        startTrainingCampMatch(a1);
      },
      "void",
      ["pointer"],
    ),
  );

  // i'm too lazy to figure out how to change it in OHD
  Interceptor.replace(
    base.add(Offsets.OnArenaChanged),
    new NativeCallback(function () {}, "void", []),
  );

  Interceptor.attach(base.add(Offsets.SettingPopupConstructor), {
    onLeave(retval) {
      let btn = addGameButton(
        retval,
        Memory.allocUtf8String("battlesettings_button"),
        1,
      );
      let setTextOffset = btn
        .readPointer()
        .add(Offsets.GameButtonSetText)
        .readPointer();
      let setText = new NativeFunction(setTextOffset, "void", [
        "pointer",
        "pointer",
        "pointer",
      ]);
      let textField = Memory.allocUtf8String("txt");
      let text = createStringObject("Battle");
      setText(btn, textField, text);
    },
  });
}
