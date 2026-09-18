import { createRemoteJWKSet, jwtVerify, SignJWT } from "jose";

const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;

const SESSION_SECRET = process.env.ADMIN_SESSION_SECRET;

const SESSION_COOKIE = "__session";

const SESSION_DURATION = 5 * 24 * 60 * 60; // 5 days

const firebaseKeys = createRemoteJWKSet(
  new URL(
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
  )
);

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed"
    });
  }

  try {
    if (!FIREBASE_PROJECT_ID) {
      throw new Error("FIREBASE_PROJECT_ID is not configured.");
    }

    if (!SESSION_SECRET) {
      throw new Error("ADMIN_SESSION_SECRET is not configured.");
    }

    const { idToken } = req.body || {};

    if (!idToken || typeof idToken !== "string") {
      return res.status(400).json({
        success: false,
        message: "Firebase ID token is required."
      });
    }

    // Verify Firebase ID token directly with Google's public keys
    const { payload } = await jwtVerify(idToken, firebaseKeys, {
      issuer: `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`,
      audience: FIREBASE_PROJECT_ID
    });

    const uid = payload.user_id || payload.sub;

    if (!uid) {
      return res.status(401).json({
        success: false,
        message: "Invalid Firebase account."
      });
    }

    /*
     * IMPORTANT:
     * We verify that the authenticated Firebase account
     * is an administrator using the Firebase REST API.
     */

    const firestoreUrl =
      `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}` +
      `/databases/(default)/documents/admins/${encodeURIComponent(uid)}`;

    const firestoreResponse = await fetch(firestoreUrl);

    if (!firestoreResponse.ok) {
      return res.status(403).json({
        success: false,
        message: "This account is not registered as an administrator."
      });
    }

    const adminDocument = await firestoreResponse.json();

    const activeField = adminDocument.fields?.active?.booleanValue;

    if (activeField !== true) {
      return res.status(403).json({
        success: false,
        message: "This administrator account is inactive."
      });
    }

    // Create our own signed admin session
    const secretKey = new TextEncoder().encode(SESSION_SECRET);

    const sessionToken = await new SignJWT({
      uid,
      admin: true
    })
      .setProtectedHeader({
        alg: "HS256",
        typ: "JWT"
      })
      .setIssuedAt()
      .setExpirationTime(`${SESSION_DURATION}s`)
      .sign(secretKey);

    res.setHeader(
      "Set-Cookie",
      `${SESSION_COOKIE}=${sessionToken}; Max-Age=${SESSION_DURATION}; Path=/; HttpOnly; Secure; SameSite=Lax`
    );

    return res.status(200).json({
      success: true,
      message: "Admin session created."
    });

  } catch (error) {
    console.error("Admin session error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to create secure administrator session."
    });
  }
}
