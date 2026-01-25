import { Offsets } from "./offsets.js";
import { PiranhaMessage } from "./piranhamessage.js";
import {
  base,
  getColumnCount,
  getCSV,
  getRowAt,
  getRowCount,
  getRowName,
  getTable,
} from "./definitions.js";
import { Messaging } from "./messaging.js";
import { ByteStream } from "./bytestream.js";
import { Logger } from "./utility/logger.js";
import { version } from "version";
import { backtrace } from "./util.js";

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

  Interceptor.replace(
    base.add(Offsets.Send),
    new NativeCallback(
      function (_self, message) {
        let type = PiranhaMessage.getMessageType(message);
        let length = PiranhaMessage.getEncodingLength(message);

        if (type === 10108) return 0;
        Logger.info("Recieved message of type:", type);
        Logger.verbose("Length:", length);
        let payloadPtr = PiranhaMessage.getByteStream(message)
          .add(Offsets.PayloadPtr)
          .readPointer();
        let payload = payloadPtr.readByteArray(length);
        if (payload !== null) {
          let stream = new ByteStream(Array.from(new Uint8Array(payload)));
          Logger.debug("Stream dump:", payload);
          Messaging.handleMessage(type, stream);
        }

        PiranhaMessage.destroyMessage(message);

        return 0;
      },
      "int",
      ["pointer", "pointer"],
    ),
  );
}
