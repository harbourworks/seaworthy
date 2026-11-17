import { observable } from "mobx";

export interface Opts {
  dangerouslyAllowBrowser: boolean;
}

@sealed
export class Settings {
  @observable accessor busy = false;
  @observable accessor options: Opts = { dangerouslyAllowBrowser: false };
  @observable.ref draft = "";
}

function sealed(target: unknown) {
  return target;
}
