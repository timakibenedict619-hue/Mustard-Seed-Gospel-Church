import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";

if (!getApps().length) {
  initializeApp({
    credential: cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
    })
  });
}

const adminAuth = getAuth();
const adminDb = getFirestore();

const SESSION_COOKIE = "__session";
const SESSION_DURATION = 5 * 24 * 60 * 60 * 1000; // 5 days

export default async function handler(req, res) {
  // Only accept POST requests
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed"
    });
  }

  try {
    const { idToken } = req.body || {};

    if (!idToken || typeof idToken !== "string") {
      return res.status(400).json({
        success: false,
        message: "Firebase ID token is required."
      });
    }

    // Verify the Firebase login token
    const decodedToken = await adminAuth.verifyIdToken(idToken);

    const uid = decodedToken.uid;

    // Check whether this Firebase account is registered as an admin
    const adminRef = adminDb.collection("admins").doc(uid);
    const adminSnap = await adminRef.get();

    if (!adminSnap.exists) {
      return res.status(403).json({
        success: false,
        message: "This account is not registered as an administrator."
      });
    }

    const adminData = adminSnap.data();

    if (adminData.active !== true) {
      return res.status(403).json({
        success: false,
        message: "This administrator account is inactive."
      });
    }

    // Create a secure Firebase session cookie
    const sessionCookie = await adminAuth.createSessionCookie(idToken, {
      expiresIn: SESSION_DURATION
    });

    // Store the session in an HTTP-only cookie
    res.setHeader(
      "Set-Cookie",
      `${SESSION_COOKIE}=${sessionCookie}; Max-Age=${Math.floor(
        SESSION_DURATION / 1000
      )}; Path=/; HttpOnly; Secure; SameSite=Lax`
    );

    return res.status(200).json({
      success: true,
      message: "Admin session created."
    });

  } catch (error) {
    console.error("Admin session error:", error);

    return res.status(401).json({
      success: false,
      message: "Unable to create admin session."
    });
  }
                                        }
