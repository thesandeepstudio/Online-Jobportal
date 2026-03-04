document
  .getElementById("adminLoginForm")
  .addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value.trim();
    const errorMsg = document.getElementById("error-msg");

    // Clear previous error
    errorMsg.innerText = "";

    if (!email || !password) {
      errorMsg.innerText = "Please enter credentials.";
      return;
    }

    try {
      // Use the existing Login API
      const res = await fetch("../api/admin/login.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
        credentials: "include",
      });

      const data = await res.json();

      if (data.status) {
        // SECURITY CHECK: Is this user actually an admin?
        if (data.user.role === "admin") {
          // Success
          window.location.href = "dashboard.html";
        } else {
          // User exists, but is NOT an admin
          errorMsg.innerText = "Access Denied. Admins only.";

          // Optional: Log them out immediately if they aren't admin
          fetch("../api/logout.php");
        }
      } else {
        errorMsg.innerText = data.message || "Invalid credentials";
      }
    } catch (err) {
      console.error(err);
      errorMsg.innerText = "Server error. Check console.";
    }
  });

// Password Toggle Function
function togglePassword() {
  const input = document.getElementById("password");
  const icon = document.getElementById("passIcon");

  if (input.type === "password") {
    input.type = "text";
    icon.src = "../assets/Icons/unhide.png";
  } else {
    input.type = "password";
    icon.src = "../assets/Icons/hide.png";
  }
}
