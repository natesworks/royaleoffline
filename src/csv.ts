import {
  getBooleanValueAt,
  getCSV,
  getRowAt,
  getRowCount,
  getRowName,
  getTable,
} from "./definitions";
import { GlobalID } from "./globalid";
import { createStringObject } from "./util";
import { Logger } from "./utility/logger";

export class CSV {
  static getSpells(): number[] {
    let result: number[] = [];
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
        if (!isNotInUse) {
          result.push(GlobalID.createGlobalId(classId, i + 1 + offset));
        }
      }
      offset += rowCount;
    }

    return result;
  }

  static getCharacters() {
    let result: number[] = [];
    let spells = this.getSpells();
    spells.forEach((val) => {
      if (GlobalID.getClassId(val) == 26) result.push(val);
    });
    return result;
  }
}
