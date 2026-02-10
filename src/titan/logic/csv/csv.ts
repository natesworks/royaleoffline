import { Character } from "src/character";
import { GlobalId } from "src/globalid";
import { base } from "src/base";
import { SCString } from "src/titan/utils/scstring";
import { Logger } from "src/logger";

const getCSV = new NativeFunction(base.add(0x227c19), "pointer", ["pointer"]);
const getTable = new NativeFunction(base.add(0x25e329), "pointer", ["pointer"]);
const getRowCount = new NativeFunction(base.add(0x25f179), "int", ["pointer"]);
const getRowAt = new NativeFunction(base.add(0x25f01d), "pointer", [
  "pointer",
  "int",
]);
const getValueAt = new NativeFunction(base.add(0x25ee41), "pointer", [
  "pointer",
  "int",
  "int",
]);
const getRowName = new NativeFunction(base.add(0x25e7c1), "pointer", [
  "pointer",
]);
const getBooleanValueAt = new NativeFunction(base.add(0x25e845), "bool", [
  "pointer",
  "int",
]);
const getIntegerValueAt = new NativeFunction(base.add(0x25e875), "int", [
  "pointer",
  "int",
]);

export class CSV {
  static getSpells(): Character[] {
    let result: Character[] = [];
    const csvs = [
      "csv_logic/spells_characters.csv",
      "csv_logic/spells_buildings.csv",
      "csv_logic/spells_other.csv",
    ];

    let offset = 0;
    let rarities = this.getRarities();
    for (let i = 0; i < csvs.length; i++) {
      let classId = 26 + i;
      let csv = getCSV(new SCString(csvs[i]).ptr);
      let table = getTable(csv);
      let rowCount = getRowCount(table);
      for (let i = 0; i < rowCount; i++) {
        let row = getRowAt(table, i);
        let isNotInUse = getBooleanValueAt(row, 6);
        if (!isNotInUse) {
          let rarity = SCString.fromPtr(getValueAt(table, 3, i)).readContents();
          let level = rarities.get(rarity);
          if (!level) {
            Logger.warn("Rarity", rarity, "does not exist");
            level = 1;
          }

          let globalId = GlobalId.createGlobalId(classId, i);
          let cardId = i + 1 + offset;
          //Logger.debug("GlobalId", globalId, "CardId", cardId);

          result.push(new Character(globalId, cardId, level));
        }
      }
      offset += rowCount;
    }

    return result;
  }

  static getCharacters(): Character[] {
    let result: Character[] = [];
    let spells = this.getSpells();
    spells.forEach((val) => {
      if (GlobalId.getClassId(val.globalId) == 26) result.push(val);
    });
    return result;
  }

  static getBuildings(): Character[] {
    let result: Character[] = [];
    let spells = this.getSpells();
    spells.forEach((val) => {
      if (GlobalId.getClassId(val.globalId) == 27) result.push(val);
    });
    return result;
  }

  static getRarities(): Map<string, number> {
    let result: Map<string, number> = new Map<string, number>();
    let csv = getCSV(new SCString("csv_logic/rarities.csv").ptr);
    let table = getTable(csv);
    let rowCount = getRowCount(table);
    for (let i = 0; i < rowCount; i++) {
      let row = getRowAt(table, i);
      let name = SCString.fromPtr(getRowName(row)).readContents();
      let level = getIntegerValueAt(row, 1);
      result.set(name, level);
      //Logger.debug(name, level);
    }

    return result;
  }
}
