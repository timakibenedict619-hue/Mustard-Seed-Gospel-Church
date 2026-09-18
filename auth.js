import { auth, db } from "./firebase.js";

import {
  onAuthStateChanged,
  signOut
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";

import {
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";


/* =====================================================
   ADMIN AUTH CONFIGURATION
===================================================== */

const LOGIN_PAGE = "/admin-login.html";


/* =====================================================
   PREVENT ADMIN PAGE FLASH
===================================================== */

document.documentElement.style.visibility = "hidden";


/* =====================================================
   REDIRECT TO LOGIN
===================================================== */

function redirectToLogin() {

  window.location.replace(LOGIN_PAGE);

}


/* =====================================================
   CHECK ADMIN
===================================================== */

async function checkAdmin(user) {

  try {

    const adminRef = doc(
      db,
      "admins",
      user.uid
    );

    const adminSnap =
      await getDoc(adminRef);


    /* ---------------------------------------------
       USER DOES NOT EXIST IN ADMINS COLLECTION
    --------------------------------------------- */

    if (!adminSnap.exists()) {

      console.warn(
        "Access denied: user is not an administrator."
      );

      await signOut(auth);

      redirectToLogin();

      return false;

    }


    /* ---------------------------------------------
       GET ADMIN DATA
    --------------------------------------------- */

    const adminData =
      adminSnap.data();


    /* ---------------------------------------------
       ADMIN ACCOUNT IS INACTIVE
    --------------------------------------------- */

    if (adminData.active !== true) {

      console.warn(
        "Access denied: administrator account is inactive."
      );

      await signOut(auth);

      redirectToLogin();

      return false;

    }


    /* ---------------------------------------------
       ADMIN VERIFIED
    --------------------------------------------- */

    console.log(
      "Administrator authenticated:",
      user.email
    );


    return true;

  } catch (error) {

    console.error(
      "Admin authentication error:",
      error
    );


    try {

      await signOut(auth);

    } catch (_) {}


    redirectToLogin();

    return false;

  }

}


/* =====================================================
   AUTH STATE LISTENER
===================================================== */

onAuthStateChanged(
  auth,
  async (user) => {

    /* ---------------------------------------------
       NOT LOGGED IN
    --------------------------------------------- */

    if (!user) {

      redirectToLogin();

      return;

    }


    /* ---------------------------------------------
       VERIFY ADMIN
    --------------------------------------------- */

    const isAdmin =
      await checkAdmin(user);


    if (!isAdmin) {

      return;

    }


    /* ---------------------------------------------
       ADMIN VERIFIED
       SHOW THE PAGE
    --------------------------------------------- */

    document.documentElement.style.visibility =
      "visible";

  }
);
