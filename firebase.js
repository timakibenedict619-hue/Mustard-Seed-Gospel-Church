// Firebase configuration and initialization
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getAuth
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  getFirestore
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";

// Your Firebase project configuration
const firebaseConfig = {
  apiKey: "AIzaSyD0ZjOwRkk4FIaXBBGhGM0ZZnQU9Y2A2iU",
  authDomain: "mustard-seed-gospel-church.firebaseapp.com",
  projectId: "mustard-seed-gospel-church",
  storageBucket: "mustard-seed-gospel-church.firebasestorage.app",
  messagingSenderId: "621848142599",
  appId: "1:621848142599:web:deaf04e8bdd99a5b851ba2",
  measurementId: "G-NME841CJYJ"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Initialize Firebase Authentication
const auth = getAuth(app);

// Initialize Cloud Firestore
const db = getFirestore(app);

// Export Firebase services
export { app, auth, db };
