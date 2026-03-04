let jobsData = [];

document.addEventListener("DOMContentLoaded", async () => {
  // Initialize Notifications
  fetchNotifications();

  // Notification Toggle Logic
  const notifBtn = document.getElementById("notifBtn");
  const notifDropdown = document.getElementById("notifDropdown");

  notifBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    const isHidden = notifDropdown.classList.contains("hidden");
    if (isHidden) {
      notifDropdown.classList.remove("hidden");
      setTimeout(
        () => notifDropdown.classList.add("dropdown-enter-active"),
        10,
      );
    } else {
      notifDropdown.classList.remove("dropdown-enter-active");
      setTimeout(() => notifDropdown.classList.add("hidden"), 100);
    }
  });

  document.addEventListener("click", () => {
    notifDropdown.classList.remove("dropdown-enter-active");
    setTimeout(() => notifDropdown.classList.add("hidden"), 100);
  });

  // Logout Logic
  document.getElementById("logoutBtn").addEventListener("click", async () => {
    if (confirm("Are you sure you want to logout?")) {
      await fetch("../../api/logout.php");
      window.location.href = "../../auth/login.html";
    }
  });

  // Load Jobs
  loadJobs();
});

// --- CUSTOM ALERT FUNCTION ---
function showCustomAlert(title, message, type = "info") {
  const modal = document.getElementById("customAlert");
  const content = document.getElementById("customAlertContent");
  const titleEl = document.getElementById("alertTitle");
  const msgEl = document.getElementById("alertMessage");
  const iconEl = document.getElementById("alertIcon");
  const iconContainer = document.getElementById("alertIconContainer");

  titleEl.innerText = title;
  msgEl.innerText = message;

  if (type === "success") {
    iconEl.className = "fas fa-check text-3xl text-green-600";
    iconContainer.className = "mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-green-100 mb-4";
  } else if (type === "error") {
    iconEl.className = "fas fa-times text-3xl text-red-600";
    iconContainer.className = "mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-red-100 mb-4";
  } else {
    iconEl.className = "fas fa-info text-3xl text-primary";
    iconContainer.className = "mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-blue-100 mb-4";
  }

  modal.classList.remove("hidden");
  setTimeout(() => {
    content.classList.remove("scale-95", "opacity-0");
    content.classList.add("scale-100", "opacity-100");
  }, 10);
}

function closeCustomAlert() {
  const modal = document.getElementById("customAlert");
  const content = document.getElementById("customAlertContent");

  content.classList.remove("scale-100", "opacity-100");
  content.classList.add("scale-95", "opacity-0");

  setTimeout(() => {
    modal.classList.add("hidden");
  }, 300);
}

// --- NOTIFICATION FUNCTIONS ---
async function fetchNotifications() {
  try {
    const res = await fetch(`../../api/notifications.php?t=${new Date().getTime()}`);
    const result = await res.json();

    if (result.status) {
      const badge = document.getElementById("notifBadge");
      const list = document.getElementById("notifList");

      if (result.unread_count > 0) {
        badge.innerText = result.unread_count;
        badge.classList.remove("hidden");
      } else {
        badge.classList.add("hidden");
      }

      if (result.data.length > 0) {
        list.innerHTML = "";
        result.data.forEach((notif) => {
          const bgClass = notif.is_read == 0 ? "bg-blue-50" : "bg-white";
          const iconColor = notif.type === "success" ? "text-green-500" : "text-blue-500";
          const iconType = notif.type === "success" ? "fa-check-circle" : "fa-info-circle";

          list.innerHTML += `
                              <div class="px-4 py-3 border-b border-gray-50 hover:bg-gray-50 transition flex gap-3 ${bgClass}">
                                  <div class="mt-1 ${iconColor}"><i class="fas ${iconType}"></i></div>
                                  <div>
                                      <p class="text-sm text-gray-800 leading-tight">${notif.message}</p>
                                      <span class="text-[10px] text-gray-400 mt-1 block">${new Date(notif.created_at).toLocaleDateString()}</span>
                                  </div>
                              </div>
                          `;
        });
      }
    }
  } catch (err) {
    console.error("Notif Error", err);
  }
}

async function markAllRead() {
  try {
    await fetch("../../api/notifications.php", { method: "POST" });
    document.getElementById("notifBadge").classList.add("hidden");
    fetchNotifications();
  } catch (err) {
    console.error(err);
  }
}

// --- JOB LOAD FUNCTION ---
async function loadJobs() {
  try {
    const res = await fetch(`../../api/jobs/list.php?t=${new Date().getTime()}`);
    const result = await res.json();
    const grid = document.getElementById("job-grid");
    document.getElementById("loading").classList.add("hidden");

    if (result.status && result.data.length > 0) {
      jobsData = result.data;
      grid.classList.remove("hidden");
      result.data.forEach((job, index) => {
        const card = document.createElement("div");
        card.className = "border border-gray-200 rounded-xl p-5 hover:shadow-md transition bg-white flex flex-col justify-between h-full cursor-pointer group";
        card.onclick = () => openModal(index);

        let badgeColor = "bg-blue-50 text-blue-600";
        if (job.job_type === "Freelance")
          badgeColor = "bg-green-50 text-green-600";

        card.innerHTML = `
                  <div>
                      <div class="flex justify-between items-start mb-3">
                          <div class="w-10 h-10 rounded bg-gray-100 flex items-center justify-center text-gray-500 font-bold text-lg">
                              ${job.company_name.charAt(0)}
                          </div>
                          <span class="${badgeColor} text-xs font-semibold px-2 py-1 rounded">${job.job_type}</span>
                      </div>
                      <h3 class="font-bold text-gray-800 text-lg mb-1 group-hover:text-primary transition">${job.title}</h3>
                      <p class="text-sm text-gray-500 mb-4">${job.company_name} • ${job.location}</p>
                      <div class="flex gap-2 mb-4">
                          <span class="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded">${job.category}</span>
                          <span class="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded">${job.salary || "N/A"}</span>
                      </div>
                  </div>
              `;
        grid.appendChild(card);
      });
    } else {
      document.getElementById("empty-state").classList.remove("hidden");
    }
  } catch (err) {
    console.error(err);
  }
}

// --- MODAL FUNCTIONS ---
function openModal(index) {
  const job = jobsData[index];
  if (!job) return;

  // Clear previous file selection
  document.getElementById("resumeFile").value = "";
  const resumeContainer = document.getElementById("resume-upload-container");

  document.getElementById("modal-title").innerText = job.title;
  document.getElementById("modal-company").innerText = job.company_name;
  document.getElementById("modal-location").innerText = job.location;
  document.getElementById("modal-type").innerText = job.job_type;
  document.getElementById("modal-salary").innerText = job.salary || "Negotiable";
  document.getElementById("modal-desc").innerText = job.description || "No description provided.";
  document.getElementById("modal-date").innerText = new Date(job.created_at).toLocaleDateString();
  document.getElementById("modal-icon").innerText = job.company_name.charAt(0);

  const btn = document.getElementById("btn-apply");
  
  // Conditional UI logic (applied vs not applied)
  if (job.my_status) {
      resumeContainer.classList.add("hidden"); 
      btn.disabled = true;
      btn.onclick = null;
      if (job.my_status === "rejected") {
          btn.className = "px-6 py-2 bg-red-100 text-red-600 rounded-lg font-bold cursor-not-allowed border border-red-200";
          btn.innerHTML = 'Application Rejected <i class="fas fa-ban ml-2"></i>';
      } else if (job.my_status === "hired") {
          btn.className = "px-6 py-2 bg-green-100 text-green-700 rounded-lg font-bold cursor-not-allowed border border-green-200";
          btn.innerHTML = 'You are Hired! <i class="fas fa-check-circle ml-2"></i>';
      } else {
          btn.className = "px-6 py-2 bg-yellow-100 text-yellow-700 rounded-lg font-bold cursor-not-allowed border border-yellow-200";
          btn.innerHTML = 'Applied <i class="fas fa-check ml-2"></i>';
      }
  } else {
      resumeContainer.classList.remove("hidden"); 
      btn.disabled = false;
      btn.onclick = () => applyForJob(job.id);
      btn.className = "px-6 py-2 bg-primary text-white hover:bg-blue-600 rounded-lg font-bold shadow-md transition flex items-center";
      btn.innerHTML = 'Apply Now <i class="fas fa-paper-plane ml-2"></i>';
  }

  const modal = document.getElementById("jobModal");
  const content = document.getElementById("modalContent");
  modal.classList.remove("hidden");
  setTimeout(() => {
    content.classList.remove("scale-95", "opacity-0");
    content.classList.add("scale-100", "opacity-100");
  }, 10);
}

function closeModal() {
  const modal = document.getElementById("jobModal");
  const content = document.getElementById("modalContent");
  content.classList.remove("scale-100", "opacity-100");
  content.classList.add("scale-95", "opacity-0");
  setTimeout(() => modal.classList.add("hidden"), 300);
}

async function applyForJob(jobId) {
  const btn = document.getElementById("btn-apply");
  const fileInput = document.getElementById("resumeFile");

  if (fileInput.files.length === 0) {
      showCustomAlert("Resume Required", "Please attach your resume to apply for this position.", "error");
      return;
  }

  btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i> Sending...';
  btn.disabled = true;

  const formData = new FormData();
  formData.append("job_id", jobId);
  formData.append("resume", fileInput.files[0]);

  try {
    const res = await fetch("../../api/jobs/apply.php", {
      method: "POST",
      body: formData,
    });
    const result = await res.json();

    if (result.status) {
      closeModal();
      showCustomAlert(
        "Application Sent!",
        "Your application and resume have been submitted successfully.",
        "success",
      );
      setTimeout(() => location.reload(), 1500); 
    } else {
      btn.innerHTML = 'Apply Now <i class="fas fa-paper-plane ml-2"></i>';
      btn.disabled = false;
      showCustomAlert("Application Failed", result.message, "error");
    }
  } catch (err) {
    console.error(err);
    showCustomAlert(
      "Network Error",
      "Could not connect to the server. Please try again.",
      "error",
    );
    btn.disabled = false;
  }
}