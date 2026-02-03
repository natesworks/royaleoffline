import {
  getIntValue,
  getJSONNumber,
  getJSONObject,
  loadAsset,
} from "./definitions";
import { createStringObject } from "./util";

export class Config {
  level = 1;
  xp = 1;
  trophies = 6400;
  gold = 99999;
  diamonds = 99999;
  arena = 20;
}

export class ConfigHelper {
  static readConfig(): Config {
    const config = new Config();

    const configStr = createStringObject("config.json");
    loadAsset(configStr);

    const json = getJSONObject(configStr);

    const keys = Object.keys(config) as (keyof Config)[];

    for (const key of keys) {
      const keyStr = createStringObject(key as string);
      const defaultValue = config[key];

      if (typeof defaultValue === "number") {
        config[key] = getIntValue(getJSONNumber(json, keyStr)) as any;
      }
    }

    return config;
  }
}
