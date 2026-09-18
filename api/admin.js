import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import fs from "fs";
import path from "path";

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

/*
  Only these pages can be served through the protected
  admin system.
*/
const ALLOWED_ADMIN_PAGES = new Set([
  "admin-dashboard.html",
  "admin-events.html",
  "admin-sermons.html",
  "admin-live.html",
  "admin-prayer-requests.html",
  "admin-contacts-messages.html",
  "admin-giving.html",
  "admin-departments.html",
  "admin-wofbi.html",
  "admin-testimonies.html",
  "admin-media.html",
  "admin-settings.html",
  "admin-management.html"
]);

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...valueParts] = cookie.trim().split("=");

    if (key === name) {
      return decodeURIComponent(valueParts.join("="));
    }
  }

  return null;
}

function redirectToLogin(res) {
  res.statusCode = 302;
  res.setHeader("Location", "/admin-login.html");
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, private"
  );
  res.end();
}

export default async function handler(req, res) {
  try {
    /*
      Get the requested admin page from the URL.

      Example:
      /api/admin?path=admin-dashboard.html
    */
    const requestedPage = req.query?.path;

    if (
      !requestedPage ||
      typeof requestedPage !== "string" ||
      !ALLOWED_ADMIN_PAGES.has(requestedPage)
    ) {
      res.statusCode = 404;
      res.setHeader("Cache-Control", "no-store");
      return res.end("Page not found.");
    }

    /*
      Get the secure HTTP-only session cookie.
    */
    const sessionCookie = getCookie(req, SESSION_COOKIE);

    if (!sessionCookie) {
      return redirectToLogin(res);
    }

    /*
      Verify the Firebase session.
      checkRevoked = true means revoked sessions
      are also rejected.
    */
    let decodedClaims;

    try {
      decodedClaims = await adminAuth.verifySessionCookie(
        sessionCookie,
        true
      );
    } catch (error) {
      console.error("Invalid admin session:", error);
      return redirectToLogin(res);
    }

    const uid = decodedClaims.uid;

    /*
      Verify that the authenticated Firebase user
      is actually registered as an active admin.
    */
    const adminRef = adminDb.collection("admins").doc(uid);
    const adminSnap = await adminRef.get();

    if (!adminSnap.exists) {
      return redirectToLogin(res);
    }

    const adminData = adminSnap.data();

    if (adminData.active !== true) {
      return redirectToLogin(res);
    }

    /*
      The user is authenticated and is an active admin.

      Now, and only now, read the requested HTML file.
    */
    const filePath = path.join(process.cwd(), requestedPage);

    /*
      Extra protection against path traversal.
    */
    const projectRoot = path.resolve(process.cwd());
    const resolvedPath = path.resolve(filePath);

    if (!resolvedPath.startsWith(projectRoot + path.sep)) {
      res.statusCode = 403;
      res.setHeader("Cache-Control", "no-store");
      return res.end("Forbidden.");
    }

    if (!fs.existsSync(resolvedPath)) {
      res.statusCode = 404;
      res.setHeader("Cache-Control", "no-store");
      return res.end("Admin page not found.");
    }

    const html = fs.readFileSync(resolvedPath, "utf8");

    /*
      Never allow an authenticated admin page
      to be cached publicly.
    */
    res.statusCode = 200;

    res.setHeader("Content-Type", "text/html; charset=utf-8");

    res.setHeader(
      "Cache-Control",
      "private, no-store, no-cache, must-revalidate"
    );

    res.setHeader("Pragma", "no-cache");

    res.setHeader("Expires", "0");

    return res.end(html);

  } catch (error) {
    console.error("Admin page error:", error);

    /*
      Do not expose internal server errors or
      Firebase information to the visitor.
    */
    return redirectToLogin(res);
  }
}
