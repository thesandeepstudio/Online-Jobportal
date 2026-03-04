// GLOBAL VARIABLE to store pending jobs for the modal
let pendingJobsData = [];

document.addEventListener("DOMContentLoaded", () => {
  // --- RESPONSIVE SIDEBAR LOGIC ---
  const sidebar = document.getElementById("sidebar");
  const openSidebarBtn = document.getElementById("openSidebar");
  const closeSidebarBtn = document.getElementById("closeSidebar");
  const sidebarOverlay = document.getElementById("sidebarOverlay");

  const toggleSidebar = () => {
    sidebar.classList.toggle("-translate-x-full");
    sidebarOverlay.classList.toggle("hidden");
    document.body.classList.toggle("overflow-hidden");
  };

  if (openSidebarBtn) openSidebarBtn.addEventListener("click", toggleSidebar);
  if (closeSidebarBtn) closeSidebarBtn.addEventListener("click", toggleSidebar);
  if (sidebarOverlay) sidebarOverlay.addEventListener("click", toggleSidebar);

  // 1. INITIALIZE DASHBOARD
  loadStats();
  loadRecentUsers();
  loadPendingJobs();

  // 2. LOGOUT LOGIC
  const logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      if (confirm("Are you sure you want to logout?")) {
        await fetch("../api/logout.php");
        window.location.href = "login.html";
      }
    });
  }
});

// --- FUNCTION 1: Load Statistics ---
async function loadStats() {
  try {
    const res = await fetch("../api/admin/stats.php");
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    const data = await res.json();

    if (data.status) {
      document.getElementById("stat-total").innerText = data.total;
      document.getElementById("stat-seekers").innerText = data.seekers;
      document.getElementById("stat-employers").innerText = data.employers;

      const statJobs = document.getElementById("stat-jobs");
      if (statJobs && data.active_jobs) statJobs.innerText = data.active_jobs;
    } else if (data.message === "Unauthorized") {
      window.location.href = "login.html";
    }
  } catch (err) {
    console.error("Stats Error:", err);
  }
}

// --- FUNCTION 2: Load Recent Users Table ---
async function loadRecentUsers() {
  try {
    const res = await fetch("../api/admin/recent_user.php");
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    const response = await res.json();

    const tbody = document.getElementById("users-table-body");
    tbody.innerHTML = "";

    if (response.status && response.data.length > 0) {
      response.data.forEach((user) => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-gray-50 transition border-b border-gray-100";

        const roleBadge =
          user.role === "employer"
            ? `<span class="bg-purple-100 text-purple-700 py-1 px-3 rounded-full text-xs font-semibold">Employer</span>`
            : `<span class="bg-green-100 text-green-700 py-1 px-3 rounded-full text-xs font-semibold">Job Seeker</span>`;

        tr.innerHTML = `
                    <td class="px-6 py-4 font-medium text-gray-800">${user.name || "N/A"}</td>
                    <td class="px-6 py-4">${roleBadge}</td>
                    <td class="px-6 py-4 text-gray-500">${user.email}</td>
                    <td class="px-6 py-4 text-gray-500 text-xs sm:text-sm">${new Date(user.created_at).toLocaleDateString()}</td>
                    <td class="px-6 py-4"><span class="text-green-600 font-bold text-xs">Active</span></td>
                `;
        tbody.appendChild(tr);
      });
    } else {
      tbody.innerHTML = `<tr><td colspan="5" class="px-6 py-4 text-center">No recent users.</td></tr>`;
    }
  } catch (err) {
    console.error("Users Error:", err);
  }
}

// --- FUNCTION 3: Load Pending Jobs Table ---
async function loadPendingJobs() {
  try {
    const res = await fetch("../api/admin/pending_jobs.php");
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    const response = await res.json();

    const tbody = document.getElementById("pending-jobs-body");
    tbody.innerHTML = "";

    if (response.status && response.data.length > 0) {
      pendingJobsData = response.data;

      response.data.forEach((job, index) => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-yellow-50 transition border-b border-gray-100";

        tr.innerHTML = `
                    <td class="px-6 py-4 font-bold text-gray-800">${job.company_name}</td>
                    <td class="px-6 py-4">
                        ${job.title} 
                        <span class="block text-xs text-gray-400 mt-1">${job.job_type}</span>
                    </td>
                    <td class="px-6 py-4 text-gray-500 text-xs sm:text-sm">${new Date(job.created_at).toLocaleDateString()}</td>
                    <td class="px-6 py-4 text-right">
                        <button onclick="openModal(${index})" 
                            class="bg-blue-50 text-blue-600 hover:bg-blue-100 px-3 py-1 sm:px-4 sm:py-2 rounded-lg text-xs sm:text-sm font-medium transition shadow-sm border border-blue-200">
                            Review
                        </button>
                    </td>
                `;
        tbody.appendChild(tr);
      });
    } else {
      tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-4 text-center text-gray-500">No pending jobs found.</td></tr>`;
    }
  } catch (err) {
    console.error("Pending Jobs Error:", err);
  }
}

// --- FUNCTION 4: Modal Logic ---
function openModal(index) {
  const job = pendingJobsData[index];
  if (!job) return;

  document.getElementById("modal-title").innerText = job.title;
  document.getElementById("modal-company").innerText = job.company_name;
  document.getElementById("modal-location").innerText = job.location || "Remote";
  document.getElementById("modal-type").innerText = job.job_type;
  document.getElementById("modal-salary").innerText = job.salary || "Not specified";
  document.getElementById("modal-desc").innerText = job.description;

  const btnApprove = document.getElementById("btn-approve");
  const btnReject = document.getElementById("btn-reject");

  btnApprove.onclick = () => updateJobStatus(job.id, "active");
  btnReject.onclick = () => updateJobStatus(job.id, "rejected");

  btnApprove.disabled = false;
  btnApprove.innerText = "Approve & Publish";

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

  setTimeout(() => {
    modal.classList.add("hidden");
  }, 300);
}

// --- FUNCTION 5: API Call to Update Status ---
async function updateJobStatus(id, status) {
  const btnApprove = document.getElementById("btn-approve");

  if (status === "active") {
    btnApprove.innerText = "Publishing...";
    btnApprove.disabled = true;
  }

  try {
    const res = await fetch("../api/admin/update_job_status.php", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ job_id: id, status: status }),
    });

    const result = await res.json();

    if (result.status) {
      closeModal();
      loadPendingJobs();
      loadStats();
    } else {
      alert("Error: " + result.message);
      btnApprove.disabled = false;
      btnApprove.innerText = "Approve & Publish";
    }
  } catch (err) {
    console.error(err);
    alert("Server communication failed.");
    btnApprove.disabled = false;
    btnApprove.innerText = "Approve & Publish";
  }
}