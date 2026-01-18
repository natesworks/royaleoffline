import {
  getCSV,
  getRowAt,
  getRowCount,
  getRowName,
  getTable,
} from "./definitions";
import { createStringObject, decodeString } from "./util";
import { Logger } from "./utility/logger";

export class CSV {
  static getCards() {
    const csvs = [
      "csv_logic/spells_characters.csv",
      "csv_logic/spells_buildings.csv",
      "csv_logic/spells_other.csv",
    ];

    for (let i = 0; i < csvs.length; i++) {
      let csv = getCSV(createStringObject(csvs[i]));
      let table = getTable(csv);
      let rowCount = getRowCount(table);
      let row = getRowAt(table, rowCount - 1);
    }
  }
}
