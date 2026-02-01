import { create } from "domain";
import { Character } from "./character";
import {
  getBooleanValueAt,
  getCSV,
  getIntegerValueAt,
  getRowAt,
  getRowCount,
  getRowName,
  getTable,
  getValueAt,
} from "./definitions";
import { GlobalId } from "./globalid";
import { createStringObject, decodeString } from "./util";
import { Logger } from "./utility/logger";

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
      let csv = getCSV(createStringObject(csvs[i]));
      let table = getTable(csv);
      let rowCount = getRowCount(table);
      for (let i = 0; i < rowCount; i++) {
        let row = getRowAt(table, i);
        let isNotInUse = getBooleanValueAt(row, 6);
        if (!isNotInUse) {
          let rarity = decodeString(getValueAt(table, 3, i));
          let level = rarities.get(rarity);
          if (!level) {
            Logger.warn("Rarity", rarity, "does not exist");
            level = 1;
          }
          result.push(
            new Character(
              GlobalId.createGlobalId(classId, i + 1 + offset),
              level,
            ),
          );
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
    let csv = getCSV(createStringObject("csv_logic/rarities.csv"));
    let table = getTable(csv);
    let rowCount = getRowCount(table);
    for (let i = 0; i < rowCount; i++) {
      let row = getRowAt(table, i);
      let name = decodeString(getRowName(row));
      let level = getIntegerValueAt(row, 1);
      result.set(name, level);
      //Logger.debug(name, level);
    }

    return result;
  }
}
