export interface Opts {
  dangerouslyAllowBrowser: boolean;
}

export type ClientOptions = { dangerouslyAllowBrowser?: boolean };

export class ChatStore {
  accessor count = 0;
  accessor options: Opts = { dangerouslyAllowBrowser: false };
}
