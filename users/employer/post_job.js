function showCustomAlert(title, message, type = "info") {
  /* ... */ const m = document.getElementById("customAlert"),
    c = document.getElementById("customAlertContent"),
    t = document.getElementById("alertTitle"),
    msg = document.getElementById("alertMessage"),
    icon = document.getElementById("alertIcon"),
    ic = document.getElementById("alertIconContainer");
  t.innerText = title;
  msg.innerText = message;
  if (type === "success") {
    icon.className = "fas fa-check text-3xl text-green-600";
    ic.className =
      "mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-green-100 mb-4";
  } else if (type === "error") {
    icon.className = "fas fa-times text-3xl text-red-600";
    ic.className =
      "mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-red-100 mb-4";
  } else {
    icon.className = "fas fa-info text-3xl text-primary";
    ic.className =
      "mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-blue-100 mb-4";
  }
  m.classList.remove("hidden");
  setTimeout(() => {
    c.classList.remove("scale-95", "opacity-0");
    c.classList.add("scale-100", "opacity-100");
  }, 10);
}
function closeCustomAlert() {
  const m = document.getElementById("customAlert"),
    c = document.getElementById("customAlertContent");
  c.classList.remove("scale-100", "opacity-100");
  c.classList.add("scale-95", "opacity-0");
  setTimeout(() => {
    m.classList.add("hidden");
  }, 300);
}

let confirmCallback = null;
function showCustomConfirm(title, message, callback) {
  confirmCallback = callback;
  document.getElementById("confirmTitle").innerText = title;
  document.getElementById("confirmMessage").innerText = message;
  const m = document.getElementById("customConfirm"),
    c = document.getElementById("confirmContent");
  m.classList.remove("hidden");
  setTimeout(() => {
    c.classList.remove("scale-95", "opacity-0");
    c.classList.add("scale-100", "opacity-100");
  }, 10);
}
function closeCustomConfirm() {
  const m = document.getElementById("customConfirm"),
    c = document.getElementById("confirmContent");
  c.classList.remove("scale-100", "opacity-100");
  c.classList.add("scale-95", "opacity-0");
  setTimeout(() => {
    m.classList.add("hidden");
  }, 300);
  confirmCallback = null;
}
document.getElementById("confirmBtnAction").addEventListener("click", () => {
  if (confirmCallback) confirmCallback();
  closeCustomConfirm();
});
function confirmLogout() {
  showCustomConfirm("Logout", "Are you sure you want to log out?", async () => {
    await fetch("../../api/logout.php");
    window.location.href = "../../auth/login.html";
  });
}

document.getElementById("postJobForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const data = {
    title: document.getElementById("title").value,
    category: document.getElementById("category").value,
    job_type: document.getElementById("job_type").value,
    salary: document.getElementById("salary").value,
    location: document.getElementById("location").value,
    description: document.getElementById("description").value,
  };

  try {
    const res = await fetch("../../api/jobs/create.php", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    const result = await res.json();

    if (result.status) {
      showCustomAlert(
        "Job Posted!",
        "Your job is now pending admin approval.",
        "success",
      );
      setTimeout(() => (window.location.href = "dashboard.html"), 2000);
    } else {
      showCustomAlert(
        "Failed",
        result.message || "Could not post job.",
        "error",
      );
      if (result.message.includes("Unauthorized"))
        window.location.href = "../../auth/login.html";
    }
  } catch (err) {
    showCustomAlert("Error", "Server connection failed.", "error");
  }
});
