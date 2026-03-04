document.addEventListener("DOMContentLoaded", () => {
  // --- 1. ELEMENT SELECTORS ---
  const jobForm = document.getElementById("jobseeker-form");
  const empForm1 = document.getElementById("employer-form");
  const empForm2 = document.getElementById("employer-detail-form");
  const radioInputs = document.querySelectorAll("input[name='userType']");
  const continueBtn = document.getElementById("continueBtn");

  // --- 2. TOGGLE USER TYPE ---
  radioInputs.forEach((radio) => {
    radio.addEventListener("change", (e) => {
      if (e.target.value === "jobseeker") {
        jobForm.classList.remove("hidden");
        empForm1.classList.add("hidden");
        empForm2.classList.add("hidden");
      } else {
        jobForm.classList.add("hidden");
        empForm1.classList.remove("hidden");
        empForm2.classList.add("hidden");
      }
    });
  });

  // --- 3. DROPDOWN LOGIC ---
  const customSelects = document.querySelectorAll(".custom-select");
  customSelects.forEach((select) => {
    const selectedDisplay = select.querySelector(".selected");
    const optionsContainer = select.querySelector(".options");
    const inputId = select.getAttribute("data-name") + "Input";
    const realInput = document.getElementById(inputId);

    selectedDisplay.addEventListener("click", (e) => {
      e.stopPropagation();
      document.querySelectorAll(".options").forEach((opt) => {
        if (opt !== optionsContainer) opt.classList.add("hidden");
      });
      optionsContainer.classList.toggle("hidden");
    });

    select.querySelectorAll(".options div").forEach((option) => {
      option.addEventListener("click", (e) => {
        e.stopPropagation();
        selectedDisplay.childNodes[0].nodeValue = option.innerText + " ";
        if (realInput) realInput.value = option.innerText;
        optionsContainer.classList.add("hidden");
      });
    });
  });

  document.addEventListener("click", () => {
    document
      .querySelectorAll(".options")
      .forEach((opt) => opt.classList.add("hidden"));
  });

  continueBtn.addEventListener("click", () => {
    const size = document.getElementById("companySizeInput").value;
    const industry = document.getElementById("industryInput").value;
    if (!size || !industry) {
      alert("Please select both Company Size and Industry.");
      return;
    }
    empForm1.classList.add("hidden");
    empForm2.classList.remove("hidden");
  });

  // --- 4. PASSWORD TOGGLE ---
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

  // --- 5. HELPER: SHOW ERROR ---
  function showError(elementId, message) {
    const el = document.getElementById(elementId);
    if (el) el.innerText = message;
  }

  function clearErrors() {
    [
      "js-email-error",
      "js-general-error",
      "emp-email-error",
      "emp-general-error",
    ].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.innerText = "";
    });
  }

  // --- 6. SMART EMAIL VALIDATION ---
  function validateEmailSmart(email) {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!regex.test(email)) {
      return { valid: false, msg: "Invalid email format." };
    }

    const domain = email.split("@")[1].toLowerCase();
    const typos = {
      "gmai.com": "gmail.com",
      "gmial.com": "gmail.com",
      "gmil.com": "gmail.com",
      "yaho.com": "yahoo.com",
      "yahho.com": "yahoo.com",
      "outlok.com": "outlook.com",
      "hotmai.com": "hotmail.com",
    };

    if (typos[domain]) {
      return { valid: false, msg: `Did you mean '${typos[domain]}'?` };
    }
    return { valid: true };
  }

  // --- 7. STRONG PASSWORD VALIDATION (NEW) ---
  function validatePasswordSmart(password, email) {
    // A. Minimum Length
    if (password.length < 8) {
      return { valid: false, msg: "Password must be at least 8 characters." };
    }
    // B. Capital Letter
    if (!/[A-Z]/.test(password)) {
      return {
        valid: false,
        msg: "Password must contain at least one uppercase letter.",
      };
    }
    // C. Number
    if (!/[0-9]/.test(password)) {
      return {
        valid: false,
        msg: "Password must contain at least one number.",
      };
    }
    // D. Special Character
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      return {
        valid: false,
        msg: "Password must contain at least one special character (!@#$%).",
      };
    }
    // E. Cannot contain Email (Username part)
    if (email) {
      const username = email.split("@")[0];
      if (password.toLowerCase().includes(username.toLowerCase())) {
        return {
          valid: false,
          msg: "Password cannot contain your email username.",
        };
      }
    }

    return { valid: true };
  }

  // --- 8. JOB SEEKER SUBMIT ---
  document
    .getElementById("registerBtn")
    .addEventListener("click", async (e) => {
      e.preventDefault();
      clearErrors();

      const data = {
        role: "jobseeker",
        first_name: document.getElementById("first_name").value.trim(),
        last_name: document.getElementById("last_name").value.trim(),
        email: document.getElementById("email_id").value.trim(),
        mobile: document.getElementById("mobile_number").value.trim(),
        password: document.getElementById("password").value.trim(),
        confirm: document.getElementById("confirm-password").value.trim(),
      };

      // Empty Check
      if (
        !data.first_name ||
        !data.last_name ||
        !data.email ||
        !data.password
      ) {
        showError("js-general-error", "Please fill in all fields.");
        return;
      }

      // Email Check
      const emailCheck = validateEmailSmart(data.email);
      if (!emailCheck.valid) {
        showError("js-email-error", emailCheck.msg);
        return;
      }

      // Password Check (NEW)
      const passCheck = validatePasswordSmart(data.password, data.email);
      if (!passCheck.valid) {
        showError("js-general-error", passCheck.msg);
        return;
      }

      // Password Match
      if (data.password !== data.confirm) {
        showError("js-general-error", "Passwords do not match.");
        return;
      }

      sendRegister(data, "js-general-error");
    });

  // --- 9. EMPLOYER SUBMIT ---
  document
    .getElementById("employersRegisterBtn")
    .addEventListener("click", async (e) => {
      e.preventDefault();
      clearErrors();

      const data = {
        role: "employer",
        company_size: document.getElementById("companySizeInput").value,
        industry: document.getElementById("industryInput").value,
        company_name: document.getElementById("company_name").value.trim(),
        location: document.getElementById("company_location").value.trim(),
        email: document.getElementById("company_email").value.trim(),
        mobile: document.getElementById("company_mobile").value.trim(),
        password: document.getElementById("company_password").value.trim(),
        confirm: document
          .getElementById("company_confirm_password")
          .value.trim(),
      };

      if (!data.company_name || !data.email || !data.password) {
        showError("emp-general-error", "Please fill in all fields.");
        return;
      }

      const emailCheck = validateEmailSmart(data.email);
      if (!emailCheck.valid) {
        showError("emp-email-error", emailCheck.msg);
        return;
      }

      // Password Check (NEW)
      const passCheck = validatePasswordSmart(data.password, data.email);
      if (!passCheck.valid) {
        showError("emp-general-error", passCheck.msg);
        return;
      }

      if (data.password !== data.confirm) {
        showError("emp-general-error", "Passwords do not match.");
        return;
      }

      sendRegister(data, "emp-general-error");
    });

  // --- 10. API CALL ---
  async function sendRegister(payload, errorFieldId) {
    try {
      const res = await fetch("../api/register.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const result = await res.json();

      if (result.status) {
        alert("Registration Successful! Please Login.");
        window.location.href = "login.html";
      } else {
        showError(errorFieldId, result.message || "Registration failed");
      }
    } catch (err) {
      console.error(err);
      showError(errorFieldId, "Server connection failed.");
    }
  }
});
