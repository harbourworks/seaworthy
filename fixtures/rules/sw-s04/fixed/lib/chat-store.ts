export class ChatStore {
  accessor count = 0;
  accessor draft: string = "";

  async send(message: string) {
    // The key stays on the server; the browser calls our own route.
    const res = await fetch("/api/chat", { method: "POST", body: JSON.stringify({ message }) });
    this.count++;
    return res.json();
  }
}
