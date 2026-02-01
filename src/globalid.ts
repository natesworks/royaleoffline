export class GlobalId {
  static createGlobalId(classId: number, instanceId: number): number {
    return classId <= 0 ? 1000000 + instanceId : classId * 1000000 + instanceId;
  }

  static getClassId(globalId: number): number {
    return Math.floor(globalId / 1000000);
  }

  static getInstanceId(globalId: number): number {
    return globalId % 1000000;
  }
}
