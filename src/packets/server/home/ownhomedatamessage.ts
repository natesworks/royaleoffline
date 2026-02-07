import { ByteStream } from "src/bytestream";
import { ConfigHelper } from "src/config";
import { CSV } from "src/csv";
import { userdata } from "src/definitions";
import { GlobalId } from "src/globalid";

export class OwnHomeDataMessage {
  messagePayload: number[];

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  static encode(): number[] {
    let stream = new ByteStream([]);
    const characters = CSV.getSpells();
    const config = ConfigHelper.readConfig();
    const decks = userdata.decks;

    // LogicClientHome
    stream.writeLong(0, 1); // player id

    stream.writeVInt(0);

    stream.writeVInt(1); // free chest id
    // timer
    for (let i = 0; i < 3; i++) stream.writeVInt(0);

    stream.writeVInt(0); // last login timestamp

    stream.writeVInt(decks.decks.length); // deck count
    for (let i = 0; i < decks.decks.length; i++) {
      let deck = decks.decks[i];
      stream.writeVInt(8);
      for (let j = 0; j < 8; j++) {
        let character = deck.characters[j];
        stream.writeVInt(character.globalId);
      }
    }

    for (let i = 0; i < 8; i++) {
      stream.writeBoolean(true);
    }

    const currentDeck = decks.decks[decks.selected];
    for (let i = 0; i < 8; i++) {
      const character = currentDeck.characters[i];
      stream.writeVInt(character.cardId);
      stream.writeVInt(character.level - 1); // level
      stream.writeVInt(0);
      stream.writeVInt(0); // count
      stream.writeVInt(0);
      stream.writeVInt(0);
      stream.writeBoolean(false);
      stream.writeBoolean(false);
    }

    stream.writeVInt(characters.length);
    for (let i = 0; i < characters.length; i++) {
      const character = characters[i];
      stream.writeVInt(character.cardId);
      stream.writeVInt(character.level - 1); // level
      stream.writeVInt(0);
      stream.writeVInt(0); // count
      stream.writeVInt(0);
      stream.writeVInt(0);
      stream.writeBoolean(false);
      stream.writeBoolean(false);
    }

    stream.writeVInt(decks.selected);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeByte(0x7f);

    stream.writeVInt(33);
    stream.writeVInt(0); // current timestamp
    stream.writeVInt(1);
    stream.writeVInt(0);

    stream.writeVInt(1); // arr
    stream.writeVInt(1109);
    stream.writeString("2v2 Button");

    stream.writeVInt(8);

    stream.writeVInt(0);
    stream.writeVInt(-1); // timestamp when event ends; when negative it doesn't show
    stream.writeVInt(0);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeString("2v2 Button");
    stream.writeString('{"HideTimer":true,"HidePopupTimer":false}"');

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeByte(0x7f);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(0); // challenge events

    stream.writeVInt(1); // events
    stream.writeVInt(1109);

    stream.writeVInt(2);

    stream.writeVInt(2);
    stream.writeString('{"ID":"CARD_RELEASE","Params":{}})');

    stream.writeVInt(4);
    stream.writeString('{"ID":"CLAN_CHEST","Params":{}}');

    // chests
    stream.writeVInt(4);
    stream.writeVInt(0);

    stream.writeVInt(0); // free chest timer
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeBoolean(false);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(0); // crowns
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(-1);
    stream.writeVInt(1714640);
    stream.writeVInt(1726960);
    stream.writeVInt(0);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(-1);

    stream.writeVInt(userdata.registered ? 3 : 1); // 1 = SetNamePopup, 2 = Upgrade Card Tutorial, 3 = NameSet

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(2);
    stream.writeVInt(config.level); // xp level

    stream.writeDataReference(GlobalId.createGlobalId(54, 0));

    //shop
    stream.writeVInt(1); // shop day
    stream.writeVInt(1); // seed
    stream.writeVInt(1); // day seen

    stream.writeVInt(0); // ticks until tmrw
    stream.writeVInt(0);

    stream.writeVInt(0);

    stream.writeVInt(0); // offer count

    stream.writeVInt(0); // special

    for (var i = 0; i < 3; i++) {
      stream.writeVInt(0);
      stream.writeVInt(0);
      stream.writeVInt(0);
    }

    stream.writeVInt(1);
    stream.writeVInt(0);

    stream.writeVInt(1);
    stream.writeVInt(0);

    stream.writeVInt(1);
    stream.writeVInt(0);

    stream.writeVInt(1);
    stream.writeVInt(0);

    stream.writeVInt(0);

    stream.writeVInt(0); // Card request?

    stream.writeVInt(0);

    stream.writeVInt(23);

    // Array
    stream.writeVInt(0);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeShort(-2041);

    stream.writeVInt(1);
    stream.writeVInt(1);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(11);
    stream.writeVInt(0);

    stream.writeVInt(2);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(4);
    stream.writeVInt(3);
    stream.writeVInt(17);
    stream.writeVInt(1);

    stream.writeVInt(14);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(5);
    stream.writeVInt(4);
    stream.writeVInt(14);
    stream.writeVInt(1);

    stream.writeVInt(74);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(5);
    stream.writeVInt(4);
    stream.writeVInt(1);
    stream.writeVInt(1);

    stream.writeVInt(73);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(1);
    stream.writeVInt(0);
    stream.writeVInt(5);
    stream.writeVInt(0);

    stream.writeVInt(4);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(1);
    stream.writeVInt(0);
    stream.writeVInt(9);
    stream.writeVInt(0);

    stream.writeVInt(15);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(1);
    stream.writeVInt(1);
    stream.writeVInt(6);
    stream.writeVInt(2);

    stream.writeVInt(16);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(1);
    stream.writeVInt(1);
    stream.writeVInt(6);
    stream.writeVInt(2);

    stream.writeVInt(0);

    // Missions
    stream.writeVInt(0);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(1);
    stream.writeVInt(0);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(0); // New Arenas Seen Count

    stream.writeVInt(0); // Session Reward = 2
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(7); // Training Battles completed

    // end client home
    // client avatar

    // Id - Account Id - HomeId
    for (let i = 0; i < 3; i++) {
      stream.writeVLong(0, 1); // id
    }

    stream.writeString(userdata.name);
    stream.writeBoolean(false); // name change state

    stream.writeVInt(config.arena); // current arena; TODO: fix

    stream.writeVInt(config.trophies); // trophies

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0); // Legendary Trophies

    stream.writeVInt(0); // Current Season Trophies
    stream.writeVInt(0);
    stream.writeVInt(0); // Displays near League // maybe never used

    stream.writeVInt(0); // Best Season Trophies
    stream.writeVInt(0); // Rank
    stream.writeVInt(0); // Trophies

    // League
    stream.writeVInt(0); // Current Trophies
    stream.writeVInt(0); // Past Trophies
    stream.writeVInt(1);
    stream.writeVInt(0);
    stream.writeVInt(0); // set this 1 and it appears on the profile

    stream.writeVInt(8);

    // Game Variables
    stream.writeVInt(10);
    stream.writeVInt(5);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(5);
    stream.writeVInt(1);
    stream.writeVInt(config.gold); // Gold

    stream.writeVInt(5);
    stream.writeVInt(3);
    stream.writeVInt(2);

    stream.writeVInt(5); // New Crowns
    stream.writeVInt(4);
    stream.writeVInt(0);

    stream.writeVInt(5);
    stream.writeVInt(5);
    stream.writeVInt(config.gold); // Gold

    stream.writeVInt(5);
    stream.writeVInt(13);
    stream.writeVInt(0); // New Gold

    stream.writeVInt(5);
    stream.writeVInt(14);
    stream.writeVInt(0);

    stream.writeVInt(5);
    stream.writeVInt(16);
    stream.writeVInt(51);

    stream.writeVInt(5);
    stream.writeVInt(28);
    stream.writeVInt(0);

    stream.writeVInt(5);
    stream.writeVInt(29);
    stream.writeVInt(72000006);

    stream.writeVInt(0); // Completed Achievements

    // Achievements
    stream.writeVInt(0); // Achievement Count
    stream.writeVInt(0); // Achievement Count

    // Profile Statistics
    stream.writeVInt(6);
    stream.writeVInt(5);
    stream.writeVInt(6);
    stream.writeVInt(30);

    stream.writeVInt(5);
    stream.writeVInt(7);
    stream.writeVInt(0); // Three Crown Win Count

    stream.writeVInt(5);
    stream.writeVInt(8);
    stream.writeVInt(characters.length); // Cards found

    stream.writeVInt(5);
    stream.writeVInt(1); // Count
    stream.writeVInt(26000048); // CardId

    stream.writeVInt(5);
    stream.writeVInt(11);
    stream.writeVInt(32);

    stream.writeVInt(5);
    stream.writeVInt(27);
    stream.writeVInt(1);

    stream.writeVInt(0);
    stream.writeVInt(0); // NPC? / Count?
    stream.writeVInt(0);

    stream.writeVInt(config.diamonds); // Diamonds
    stream.writeVInt(config.diamonds); // FreeDiamonds

    stream.writeVInt(config.xp); // ExpPoints
    stream.writeVInt(config.level); // ExpLevel

    stream.writeVInt(0); // AvatarUserLevelTier

    stream.writeVInt(userdata.registered ? 7 : 6); // HasAlliance

    // Battle Statistics
    stream.writeVInt(0); // Games Played
    stream.writeVInt(0); // Tournament Matches Played
    stream.writeVInt(0);
    stream.writeVInt(0); // Wins
    stream.writeVInt(0); // Losses

    stream.writeVInt(0);

    stream.writeVInt(7);

    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(0); // Has Challenge
    //  stream.writeVInt(); // ID
    //  stream.writeVInt(0); // WINS
    //  stream.writeVInt(0); // LOSSES

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(0);
    stream.writeVInt(0); // AccountCreated
    stream.writeVInt(0); // PlayTime

    return stream.payload;
  }

  getMessageType() {
    return 24101;
  }
}
