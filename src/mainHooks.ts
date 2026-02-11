import { battleSettings, buttonHandlers, userdata } from "./definitions";
import { Messaging } from "./messaging";
import { Logger } from "./logger";
import { backtrace } from "./util";
import { base } from "./base";
import { PiranhaMessage } from "./titan/logic/message/piranhamessage";

const startTrainingCampMatch = new NativeFunction(base.add(0x14fef1), "void", [
  "pointer",
]);
const isOwnedByAI = new NativeFunction(base.add(0x1ad9ed), "bool", ["pointer"]);

export function installHooks() {
  Interceptor.attach(base.add(0x260f3d), {
    onEnter(args) {
      let text = args[0].readUtf8String();
      Logger.warn(text);
    },
  });

  Interceptor.attach(base.add(0x261181), {
    onEnter(args) {
      Logger.error(args[0].readUtf8String());
      Logger.debug("Backtrace:");
      backtrace(this.context);
    },
  });

  Interceptor.attach(base.add(0x9e615), {
    onEnter(args) {
      let messaging = args[0].add(4).readPointer();
      let connection = messaging.add(64);
      connection.add(4).writeU8(5);
    },
  });

  Memory.patchCode(base.add(0x1c0120), Process.pageSize, (code) => {
    const pcWriter = new ThumbWriter(code);
    pcWriter.putBranchAddress(base.add(0x1c0146));
    pcWriter.flush();
  });

  Interceptor.attach(base.add(0x99561), {
    onEnter(args) {
      PiranhaMessage.encode(args[1]);
      let messaging = args[0].add(4).readPointer();
      messaging.add(4).writeInt(5);
    },
  });

  Interceptor.replace(
    base.add(0x1fafb1),
    new NativeCallback(
      function (_self, message) {
        let type = PiranhaMessage.getMessageType(message);
        let length = PiranhaMessage.getEncodingLength(message);

        Logger.info("Recieved message of type:", type);
        Logger.verbose("Length:", length);

        let payloadPtr = PiranhaMessage.getByteStream(message)
          .add(28)
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
    base.add(0x9d01d),
    new NativeCallback(function () {}, "void", []),
  );

  Interceptor.replace(
    base.add(0x8eb39),
    new NativeCallback(function () {}, "void", []),
  );

  Interceptor.replace(
    base.add(0x14d851),
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
    base.add(0xae715),
    new NativeCallback(function () {}, "void", []),
  );

  Interceptor.attach(base.add(0x121431), {
    onLeave(settingsPopup) {
      battleSettings.createSettingsButton(settingsPopup);
    },
  });

  Interceptor.attach(base.add(0x1226ad), {
    onEnter(args) {
      if (
        battleSettings.settingsButton &&
        args[1].equals(battleSettings.settingsButton.ptr)
      ) {
        battleSettings.createPopup();
        battleSettings.show();
      }
    },
  });

  Interceptor.attach(base.add(0xe9a61), {
    onLeave(combatHUD) {
      battleSettings.createBattleButton(combatHUD);
    },
  });

  Interceptor.attach(base.add(0x2592b1), {
    onEnter(args) {
      const clicked = args[0];

      for (const entry of buttonHandlers) {
        if (entry.ptr.equals(clicked)) {
          entry.handler(clicked);
          break;
        }
      }
    },
  });

  Interceptor.attach(base.add(0x25c385), {
    onEnter(args) {
      const clicked = args[0];

      for (const entry of buttonHandlers) {
        if (entry.ptr.equals(clicked)) {
          entry.handler(clicked);
          break;
        }
      }
    },
  });

  Interceptor.attach(base.add(0x1b39e5), {
    onEnter(args) {
      this.a1 = args[0];
    },
    onLeave(retval) {
      if (userdata.infiniteElixirEnabled && !isOwnedByAI(this.a1))
        retval.replace(ptr(10));
    },
  });

  Interceptor.attach(base.add(0x1b39dd), {
    onEnter(args) {
      this.a1 = args[0];
    },
    onLeave(retval) {
      if (userdata.infiniteElixirEnabled && !isOwnedByAI(this.a1))
        retval.replace(ptr(10));
    },
  });
}
