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
   ADMIN AUTH GUARD
===================================================== */

const LOGIN_PAGE = "/admin-login.html";


/* =====================================================
   HIDE PAGE IMMEDIATELY
===================================================== */

const hidePage = () => {

  document.documentElement.style.visibility = "hidden";

};


/* =====================================================
   SHOW PAGE AFTER AUTHENTICATION
===================================================== */

const showPage = () => {

  document.documentElement.style.visibility = "visible";

};


/* =====================================================
   REDIRECT
===================================================== */

const redirectToLogin = () => {

  window.location.replace(LOGIN_PAGE);

};


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


    /* USER IS NOT AN ADMIN */

    if (!adminSnap.exists()) {

      await signOut(auth);

      redirectToLogin();

      return false;

    }


    const adminData =
      adminSnap.data();


    /* ADMIN IS INACTIVE */

    if (adminData.active !== true) {

      await signOut(auth);

      redirectToLogin();

      return false;

    }


    /* ADMIN IS VALID */

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
   START AUTH CHECK
===================================================== */

hidePage();


onAuthStateChanged(
  auth,
  async (user) => {

    /* -----------------------------------------------
       NOT LOGGED IN
    ----------------------------------------------- */

    if (!user) {

      redirectToLogin();

      return;

    }


    /* -----------------------------------------------
       CHECK ADMIN
    ----------------------------------------------- */

    const isAdmin =
      await checkAdmin(user);


    if (!isAdmin) {

      return;

    }


    /* -----------------------------------------------
       VERIFIED ADMIN
    ----------------------------------------------- */

    showPage();

  }
);
