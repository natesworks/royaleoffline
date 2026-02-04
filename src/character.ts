export class Character {
  globalId;
  cardId;
  level;

  constructor(globalId: number, cardId: number, level: number) {
    this.globalId = globalId;
    this.cardId = cardId;
    this.level = level;
  }
}
