import { createRemoteJWKSet, jwtVerify, SignJWT } from "jose";

const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;
const ADMIN_UIDS = process.env.ADMIN_UIDS;
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
      throw new Error("FIREBASE_PROJECT_ID is missing.");
    }

    if (!ADMIN_UIDS) {
      throw new Error("ADMIN_UIDS is missing.");
    }

    if (!SESSION_SECRET) {
      throw new Error("ADMIN_SESSION_SECRET is missing.");
    }

    const { idToken } = req.body || {};

    if (!idToken || typeof idToken !== "string") {
      return res.status(400).json({
        success: false,
        message: "Firebase ID token is required."
      });
    }

    // Verify the Firebase ID token
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

    // Check whether this UID is an administrator
    const allowedAdmins = ADMIN_UIDS
      .split(",")
      .map(uid => uid.trim())
      .filter(Boolean);

    if (!allowedAdmins.includes(uid)) {
      return res.status(403).json({
        success: false,
        message: "This account is not registered as an administrator."
      });
    }

    // Create secure signed session
    const secretKey = new TextEncoder().encode(SESSION_SECRET);

    const sessionToken = await new SignJWT({
      uid: uid,
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
