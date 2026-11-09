import { initializeApp } from "firebase/app";
import { getFirestore } from "firebase/firestore";

const app = initializeApp({
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain: "chat-agent-fixture.firebaseapp.com",
  projectId: "chat-agent-fixture",
  storageBucket: "chat-agent-fixture.appspot.com",
});

export const db = getFirestore(app);
