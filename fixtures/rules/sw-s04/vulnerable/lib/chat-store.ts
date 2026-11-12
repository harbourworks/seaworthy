import OpenAI from "openai";

export class ChatStore {
  accessor count = 0;
  accessor draft: string = "";
}

export const openai = new OpenAI({
  apiKey: "set-at-runtime",
  dangerouslyAllowBrowser: true,
});
