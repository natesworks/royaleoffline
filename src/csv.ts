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
} from "./definitions";
import { GlobalId } from "./globalid";
import { createStringObject } from "./util";
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
    for (let i = 0; i < csvs.length; i++) {
      let classId = 26 + i;
      let csv = getCSV(createStringObject(csvs[i]));
      let table = getTable(csv);
      let rowCount = getRowCount(table);
      for (let i = 0; i < rowCount; i++) {
        let row = getRowAt(table, i);
        let isNotInUse = getBooleanValueAt(row, 6);
        let powerLevel = getIntegerValueAt(row, 47);
        if (!isNotInUse) {
          result.push(
            new Character(
              GlobalId.createGlobalId(classId, i + 1 + offset),
              powerLevel,
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
}
