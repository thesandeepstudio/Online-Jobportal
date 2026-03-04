let currentProfileData = {};

// MODAL HELPERS
function showCustomAlert(title, message, type = "info") {
  const m = document.getElementById("customAlert"),
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

// MAIN LOGIC
document.addEventListener("DOMContentLoaded", async () => {
  // --- MOBILE MENU TOGGLE ---
  const mobileMenuBtn = document.getElementById("mobileMenuBtn");
  const mobileMenu = document.getElementById("mobileMenu");

  if (mobileMenuBtn) {
    mobileMenuBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      mobileMenu.classList.toggle("open");
    });
    document.addEventListener("click", () =>
      mobileMenu.classList.remove("open"),
    );
  }

  // --- FETCH PROFILE DATA ---
  try {
    const res = await fetch("../../api/users/profile.php");
    const result = await res.json();
    if (result.status && result.data) {
      const user = result.data;
      currentProfileData = user;
      document.getElementById("display-name").innerText =
        `${user.first_name} ${user.last_name}`;
      document.getElementById("display-email").innerText = user.email;
      document.getElementById("first_name").value = user.first_name;
      document.getElementById("last_name").value = user.last_name;
      document.getElementById("bio").value = user.bio || "";
      document.getElementById("skills").value = user.skills || "";
      document.getElementById("education").value = user.education || "";
      if (user.experience)
        document.getElementById("experience").value = user.experience;

      if (user.profile_pic) {
        document.getElementById("avatar-img").src =
          "../../api/" + user.profile_pic;
        document.getElementById("avatar-img").classList.remove("hidden");
        document.getElementById("avatar-initial-box").classList.add("hidden");
      } else {
        document.getElementById("avatar-initial").innerText = user.first_name
          .charAt(0)
          .toUpperCase();
      }
    }
  } catch (err) {
    console.error(err);
  }

  // --- SAVE PROFILE ---
  document
    .getElementById("profileForm")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = document.getElementById("saveBtn");
      btn.innerText = "Saving...";
      btn.disabled = true;

      const formData = new FormData();
      formData.append(
        "first_name",
        document.getElementById("first_name").value,
      );
      formData.append("last_name", document.getElementById("last_name").value);
      formData.append("bio", document.getElementById("bio").value);
      formData.append("skills", document.getElementById("skills").value);
      formData.append(
        "experience",
        document.getElementById("experience").value,
      );
      formData.append("education", document.getElementById("education").value);

      const fileInput = document.getElementById("profilePicInput");
      if (fileInput.files.length > 0)
        formData.append("profile_pic", fileInput.files[0]);

      try {
        const res = await fetch("../../api/users/profile.php", {
          method: "POST",
          body: formData,
        });
        const result = await res.json();
        if (result.status) {
          showCustomAlert(
            "Success",
            "Profile updated successfully!",
            "success",
          );
          setTimeout(() => location.reload(), 1500);
        } else {
          showCustomAlert("Error", result.message || "Update failed.", "error");
        }
      } catch (err) {
        showCustomAlert("Error", "Server error occurred", "error");
      } finally {
        btn.innerText = "Save Changes";
        btn.disabled = false;
      }
    });

  // --- PREVIEW PROFILE ---
  document.getElementById("previewBtn").addEventListener("click", () => {
    const modal = document.getElementById("profileModal");
    const content = document.getElementById("profileContent");
    const fName = document.getElementById("first_name").value;
    const lName = document.getElementById("last_name").value;

    document.getElementById("prev-name").innerText = `${fName} ${lName}`;
    document.getElementById("prev-bio").innerText =
      document.getElementById("bio").value || "No bio provided.";
    document.getElementById("prev-edu").innerText =
      document.getElementById("education").value || "N/A";
    document.getElementById("prev-exp").innerText =
      document.getElementById("experience").value || "N/A";

    const skillsContainer = document.getElementById("prev-skills");
    skillsContainer.innerHTML = "";
    const skills = document.getElementById("skills").value;
    if (skills) {
      skills.split(",").forEach((s) => {
        if (s.trim())
          skillsContainer.innerHTML += `<span class="bg-blue-50 text-primary px-3 py-1 rounded-full text-xs border border-blue-100 font-semibold">${s.trim()}</span>`;
      });
    } else {
      skillsContainer.innerHTML =
        "<span class='text-gray-400 text-sm italic'>No skills listed.</span>";
    }

    const fileInput = document.getElementById("profilePicInput");
    const prevImg = document.getElementById("prev-avatar-img");
    const prevBox = document.getElementById("prev-avatar-box");

    if (fileInput.files.length > 0) {
      const reader = new FileReader();
      reader.onload = (e) => {
        prevImg.src = e.target.result;
        prevImg.classList.remove("hidden");
        prevBox.classList.add("hidden");
      };
      reader.readAsDataURL(fileInput.files[0]);
    } else if (currentProfileData.profile_pic) {
      prevImg.src = "../../api/" + currentProfileData.profile_pic;
      prevImg.classList.remove("hidden");
      prevBox.classList.add("hidden");
    } else {
      prevBox.innerText = fName.charAt(0).toUpperCase();
      prevImg.classList.add("hidden");
      prevBox.classList.remove("hidden");
    }

    modal.classList.remove("hidden");
    setTimeout(() => {
      content.classList.remove("scale-95", "opacity-0");
      content.classList.add("scale-100", "opacity-100");
    }, 10);
  });
});

function closeModal() {
  const m = document.getElementById("profileModal"),
    c = document.getElementById("profileContent");
  c.classList.remove("scale-100", "opacity-100");
  c.classList.add("scale-95", "opacity-0");
  setTimeout(() => {
    m.classList.add("hidden");
  }, 300);
}
