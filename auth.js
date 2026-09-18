import { auth, db } from "./firebase.js";

import {
  onAuthStateChanged,
  signOut
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";

import {
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";


/*
=====================================================
ADMIN AUTHENTICATION GUARD
=====================================================
*/

const LOGIN_PAGE = "admin-login.html";


function redirectToLogin() {
  window.location.replace(LOGIN_PAGE);
}


onAuthStateChanged(auth, async (user) => {

  /*
  -----------------------------------------------
  NO USER LOGGED IN
  -----------------------------------------------
  */

  if (!user) {

    redirectToLogin();

    return;

  }


  try {

    /*
    ---------------------------------------------
    CHECK ADMINS COLLECTION
    ---------------------------------------------
    */

    const adminRef = doc(
      db,
      "admins",
      user.uid
    );

    const adminSnap =
      await getDoc(adminRef);


    /*
    ---------------------------------------------
    USER IS NOT AN ADMIN
    ---------------------------------------------
    */

    if (!adminSnap.exists()) {

      await signOut(auth);

      redirectToLogin();

      return;

    }


    /*
    ---------------------------------------------
    CHECK ACTIVE STATUS
    ---------------------------------------------
    */

    const adminData =
      adminSnap.data();


    if (adminData.active !== true) {

      await signOut(auth);

      redirectToLogin();

      return;

    }


    /*
    ---------------------------------------------
    VERIFIED ADMIN
    ---------------------------------------------
    */

    console.log(
      "Admin authentication successful."
    );


  } catch (error) {

    console.error(
      "Admin authentication error:",
      error
    );


    try {

      await signOut(auth);

    } catch (_) {}


    redirectToLogin();

  }

});
