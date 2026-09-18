import { jwtVerify } from "jose";

const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;
const SESSION_SECRET = process.env.ADMIN_SESSION_SECRET;

const SESSION_COOKIE = "__session";

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

  for (const cookie of cookieHeader.split(";")) {
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
    if (!FIREBASE_PROJECT_ID || !SESSION_SECRET) {
      console.error("Required environment variables are missing.");
      return redirectToLogin(res);
    }

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

    const sessionToken = getCookie(req, SESSION_COOKIE);

    if (!sessionToken) {
      return redirectToLogin(res);
    }

    const secretKey = new TextEncoder().encode(SESSION_SECRET);

    let payload;

    try {
      const verified = await jwtVerify(sessionToken, secretKey, {
        algorithms: ["HS256"]
      });

      payload = verified.payload;
    } catch (error) {
      console.error("Invalid admin session:", error);
      return redirectToLogin(res);
    }

    if (payload.admin !== true || !payload.uid) {
      return redirectToLogin(res);
    }

    /*
     * Re-check that the administrator account is still active.
     * This prevents an account that has been disabled in Firestore
     * from continuing to access the protected pages.
     */

    const firestoreUrl =
      `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}` +
      `/databases/(default)/documents/admins/${encodeURIComponent(payload.uid)}`;

    const firestoreResponse = await fetch(firestoreUrl);

    if (!firestoreResponse.ok) {
      return redirectToLogin(res);
    }

    const adminDocument = await firestoreResponse.json();

    const activeField =
      adminDocument.fields?.active?.booleanValue;

    if (activeField !== true) {
      return redirectToLogin(res);
    }

    /*
     * Read the requested HTML page.
     */

    const fs = await import("fs/promises");
    const path = await import("path");

    const filePath = path.join(
      process.cwd(),
      requestedPage
    );

    const html = await fs.readFile(filePath, "utf8");

    res.statusCode = 200;

    res.setHeader(
      "Content-Type",
      "text/html; charset=utf-8"
    );

    res.setHeader(
      "Cache-Control",
      "private, no-store, no-cache, must-revalidate"
    );

    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    return res.end(html);

  } catch (error) {
    console.error("Admin page error:", error);

    return redirectToLogin(res);
  }
}
