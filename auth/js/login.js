document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("login-form");
  const emailInput = document.getElementById("email_id");
  const passwordInput = document.getElementById("password");
  const emailError = document.getElementById("emailError");

  // --- 1. PASSWORD TOGGLE LOGIC ---
  window.togglePassword = function (id, element) {
    const input = document.getElementById(id);
    const img = element.querySelector("img");

    if (input.type === "password") {
      input.type = "text";
      img.src = "../assets/Icons/unhide.png";
    } else {
      input.type = "password";
      img.src = "../assets/Icons/hide.png";
    }
  };

  // --- 2. FORM SUBMIT LOGIC ---
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    if (emailError) emailError.innerText = "";

    const email = emailInput.value.trim();
    const password = passwordInput.value.trim();

    // A. Check Empty
    if (!email || !password) {
      if (emailError) emailError.innerText = "Please fill in all fields.";
      return;
    }

    // B. Check Email Format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      if (emailError)
        emailError.innerText = "Please enter a valid email address.";
      return;
    }

    try {
      const res = await fetch("../api/login.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const contentType = res.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        throw new Error("Server Error: Received non-JSON response.");
      }

      const data = await res.json();

      if (!data.status) {
        if (emailError) emailError.innerText = data.message || "Login failed";
        return;
      }

      // --- 3. LOGIN SUCCESS ---
      localStorage.setItem("user", JSON.stringify(data.user));

      if (data.user.role === "jobseeker") {
        window.location.href = "../users/jobseeker/dashboard.html";
      } else if (data.user.role === "employer") {
        window.location.href = "../users/employer/dashboard.html";
      } else if (data.user.role === "admin") {
        window.location.href = "../admin/dashboard.html";
      } else {
        window.location.href = "../index.html";
      }
    } catch (err) {
      console.error(err);
      if (emailError)
        emailError.innerText = "Server connection error. Please try again.";
    }
  });
});
