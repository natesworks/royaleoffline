import { ByteStream } from "src/bytestream";
import { CSV } from "src/csv";
import { userdata } from "src/definitions";
import { GlobalId } from "src/globalid";

export class NpcSectorStateMessage {
  messagePayload: number[];

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  encode() {
    let stream = new ByteStream([]);

    const towers = 6; // Tower Count
    const characters = CSV.getCharacters();
    const decks = userdata.decks;

    stream.writeBoolean(false); // IsCompressed

    stream.writeVInt(0); // Time
    stream.writeVInt(0); // Checksum
    stream.writeVInt(Date.now()); // Timestamp
    stream.writeVInt(11);

    stream.writeVInt(0); // Time
    stream.writeVInt(38); // Random

    // logicbattle
    stream.writeDataReference(GlobalId.createGlobalId(9, 4));

    stream.writeVInt(7419667);
    stream.writeVInt(1);

    for (let i = 0; i < 4; i++) stream.writeByte(0x7f);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(1);
    stream.writeVInt(0);

    for (let i = 0; i < 13; i++) stream.writeByte(0);

    stream.writeVInt(8);

    for (let i = 0; i < 8; i++) stream.writeByte(0);

    stream.writeVInt(10);

    for (let i = 0; i < 11; i++) stream.writeVInt(0);

    stream.writeVInt(1);
    stream.writeVInt(2);

    for (let i = 0; i < 3; i++) {
      stream.writeVLong(0, 1);
    }

    stream.writeString(userdata.name);

    stream.writeHex(
      "08982FBE02972F0000000000200000000000080D05019A750502990B050304050400050CB90C050D00050E00050FBA0C05169F0E051991AFC6C90E051A10051C00051D9788D544000000050506843205079906050B20051409051B0A89011A00001A01001A02001A03001A04001A05001A06001A07001A08001A09001A0A001A0B001A0C001A0D001A0E001A0F001A10001A11001A12001A13001A14001A15001A16001A17001A18001A19001A1A001A1B001A1C001A1D001A1E001A1F001A20001A21001A22001A23001A24001A25001A26001A27001A28001A29001A2A001A2B001A2D001A2E001A30021B00001B01001B02001B03001B04001B05001B06001B07001B08001B09001B0A001C00001C01001C02001C03001C04001C05001C06001C07001C08001C09001C0A001C0B001C0C001C0D001C100000000B020C96AD14",
    );
    stream.writeString("Training");
    stream.writeHex("8B02B21F3100BC0DB20D099F010200000000020224017F7F00");

    stream.writeVLong(0, 1); // player id
    stream.writeByte(0);

    // ByteStreamHelper::readConstantSizeIntArray(a2, a1 + 0xC, 6);
    stream.writeVInt(1);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(7);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeByte(0); // IsReplay / Type?
    stream.writeByte(0); // IsEndConditionMatched
    stream.writeByte(0);

    stream.writeByte(1); // IsNpc

    stream.writeByte(0); // isBattleEndedWithTimeOut
    stream.writeByte(0);

    stream.writeByte(0); // hasPlayerFinishedNpcLevel
    stream.writeByte(0);

    stream.writeByte(0); // isInOvertime
    stream.writeByte(0); // isTournamentMode

    stream.writeVInt(0);

    stream.writeVInt(towers);
    stream.writeVInt(towers);

    stream.writeDataReference(GlobalId.createGlobalId(35, 1));
    stream.writeDataReference(GlobalId.createGlobalId(35, 1));
    stream.writeDataReference(GlobalId.createGlobalId(35, 1));
    stream.writeDataReference(GlobalId.createGlobalId(35, 1));

    stream.writeDataReference(GlobalId.createGlobalId(35, 0));
    stream.writeDataReference(GlobalId.createGlobalId(35, 0));

    // LogicGameObject::encodeComponent
    stream.writeVInt(1);
    stream.writeVInt(0);
    stream.writeVInt(1);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(1);

    for (let i = 0; i < towers; i++) {
      stream.writeVInt(5);
      stream.writeVInt(i);
    }

    // Player Right Princess Tower
    stream.writeVInt(12);
    stream.writeVInt(13);
    stream.writeVInt(14500); // X
    stream.writeVInt(25500); // Y
    stream.writeHex("00007F00C07C0002000000000000");

    // Enemy Left Princess Tower
    stream.writeVInt(12);
    stream.writeVInt(13);
    stream.writeVInt(3500); // X
    stream.writeVInt(6500); // Y
    stream.writeHex("00007F0080040001000000000000");

    // Player Left Princess Tower
    stream.writeVInt(12);
    stream.writeVInt(13);
    stream.writeVInt(3500); // X
    stream.writeVInt(25500); // Y
    stream.writeHex("00007F00C07C0001000000000000");

    // Enemy Right Princess Tower
    stream.writeVInt(12);
    stream.writeVInt(13);
    stream.writeVInt(14500); // X
    stream.writeVInt(6500); // Y
    stream.writeHex("00007F0080040002000000000000");

    // Enemy Crown Tower
    stream.writeVInt(12);
    stream.writeVInt(13);
    stream.writeVInt(9000); // X
    stream.writeVInt(3000); // Y
    stream.writeHex("00007F0080040000000000000000");

    stream.writeHex("000504077F7D7F0400050401007F7F0000");
    stream.writeVInt(0); // Ms before regen mana
    stream.writeVInt(6); // Mana Start
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeHex("00007F7F7F7F7F7F7F7F00");

    // Player Crown Tower
    stream.writeVInt(12);
    stream.writeVInt(13);
    stream.writeVInt(9000); // X
    stream.writeVInt(29000); // Y
    stream.writeHex("00007F00C07C0000000000000000");

    stream.writeHex("00050401047D010400040706007F7F0000");
    stream.writeVInt(0); // Ms before regen mana
    stream.writeVInt(6); // Elexir Start Enemy
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(0);
    stream.writeVInt(0);

    for (let i = 0; i < 8; i++) stream.writeVInt(-1);

    for (let i = 0; i < 48; i++) stream.writeVInt(0);

    // LogicHitpointComponent
    stream.writeVInt(3668); // Enemy
    stream.writeVInt(0);
    stream.writeVInt(3668); // Player
    stream.writeVInt(0);
    stream.writeVInt(3668); // Enemy
    stream.writeVInt(0);
    stream.writeVInt(3668); // Player
    stream.writeVInt(0);
    stream.writeVInt(5832); // Enemy
    stream.writeVInt(0);
    stream.writeVInt(5832); // Player
    stream.writeVInt(0);

    // LogicCharacterBuffComponent
    for (let i = 0; i < towers; i++) stream.writeHex("00000000000000A401A401");

    // Trainer
    stream.writeHex("FF01");
    for (let i = 0; i < 8; i++) {
      const character = characters[i];
      stream.writeVInt(character.cardId);
      stream.writeVInt(character.level - 1);
    }

    stream.writeByte(0);

    // Player
    stream.writeHex("FE03");
    for (let i = 0; i < 8; i++) {
      const character = decks.decks[decks.selected].characters[i];
      stream.writeVInt(character.cardId);
      stream.writeVInt(character.level - 1);
    }

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(5);
    stream.writeVInt(6);
    stream.writeVInt(2);
    stream.writeVInt(2);
    stream.writeVInt(4);
    stream.writeVInt(2);
    stream.writeVInt(1);
    stream.writeVInt(3);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(6);
    stream.writeVInt(1);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(9);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(12);

    stream.writeHex("000000F69686FF0A002A002B");

    stream.writeVInt(0);
    stream.writeVInt(13);
    stream.writeVInt(14500);
    stream.writeVInt(25500);
    stream.writeHex("00007F00C07C0002000000000000");

    stream.writeVInt(0);
    stream.writeVInt(13);
    stream.writeVInt(3500);
    stream.writeVInt(6500);
    stream.writeHex("00007F0080040001000000000000");

    stream.writeVInt(0);
    stream.writeVInt(13);
    stream.writeVInt(3500);
    stream.writeVInt(25500);
    stream.writeHex("00007F00C07C0001000000000000");

    stream.writeVInt(0);
    stream.writeVInt(13);
    stream.writeVInt(14500);
    stream.writeVInt(6500);
    stream.writeHex("00007F0080040002000000000000");

    stream.writeVInt(0);
    stream.writeVInt(13);
    stream.writeVInt(9000);
    stream.writeVInt(3000);
    stream.writeHex("00007F0080040000000000000000");

    stream.writeVInt(0);
    stream.writeVInt(5);
    stream.writeVInt(1);
    stream.writeVInt(0);

    stream.writeHex("7F000000007F7F0000000100000000007F7F7F7F7F7F7F7F");
    stream.writeVInt(0);

    stream.writeVInt(0);
    stream.writeVInt(13);
    stream.writeVInt(9000);
    stream.writeVInt(29000);
    stream.writeHex("00007F00C07C0000000000000000");

    stream.writeVInt(0);
    stream.writeVInt(5);
    stream.writeVInt(4);
    stream.writeVInt(0);
    stream.writeVInt(1);
    stream.writeVInt(4);

    stream.writeHex(
      "7F020203007F7F0000000500000000007F7F7F7F7F7F7F7F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    );

    stream.writeVInt(0);
    stream.writeVInt(1400);

    stream.writeVInt(0);
    stream.writeVInt(560);

    stream.writeVInt(0);
    stream.writeVInt(1400);

    stream.writeVInt(0);
    stream.writeVInt(560);

    stream.writeVInt(0);
    stream.writeVInt(960);

    stream.writeVInt(0);
    stream.writeVInt(2400);

    for (let i = 0; i < towers; i++) stream.writeHex("00000000000000A401A401");

    this.messagePayload = stream.payload;
  }

  getMessageType() {
    return 21903;
  }
}
