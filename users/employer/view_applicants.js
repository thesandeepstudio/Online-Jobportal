document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("logoutBtn").addEventListener("click", async () => {
    await fetch("../../api/logout.php");
    window.location.href = "../../auth/login.html";
  });

  try {
    const res = await fetch("../../api/jobs/list_employer.php");
    const result = await res.json();
    const grid = document.getElementById("jobsGrid");
    grid.innerHTML = "";

    if (result.status && result.data.length > 0) {
      result.data.forEach((job) => {
        // Highlight jobs with applicants
        const hasApplicants = job.applicant_count > 0;
        const cardClass = hasApplicants
          ? "border-l-4 border-l-primary"
          : "border-l-4 border-l-gray-200";
        const btnClass = hasApplicants
          ? "bg-primary text-white hover:bg-blue-600"
          : "bg-gray-100 text-gray-400 cursor-not-allowed";
        const link = hasApplicants
          ? `view_applicants.html?job_id=${job.id}`
          : "#";

        const html = `
                            <div class="bg-white rounded-lg shadow-sm border border-gray-100 p-6 ${cardClass} hover:shadow-md transition">
                                <div class="flex justify-between items-start">
                                    <div>
                                        <h3 class="font-bold text-gray-800 text-lg">${job.title}</h3>
                                        <p class="text-sm text-gray-500">${new Date(job.created_at).toLocaleDateString()}</p>
                                    </div>
                                    <span class="bg-gray-100 text-gray-600 text-xs px-2 py-1 rounded">${job.job_type}</span>
                                </div>

                                <div class="mt-6 flex items-center justify-between">
                                    <div>
                                        <span class="text-2xl font-bold ${hasApplicants ? "text-primary" : "text-gray-300"}">${job.applicant_count}</span>
                                        <span class="text-sm text-gray-500 ml-1">Applicants</span>
                                    </div>
                                    
                                    <a href="${link}" class="px-4 py-2 rounded-md text-sm font-medium transition ${btnClass}">
                                        View List <i class="fas fa-arrow-right ml-1"></i>
                                    </a>
                                </div>
                            </div>
                        `;
        grid.innerHTML += html;
      });
    } else {
      grid.innerHTML = `<p class="col-span-3 text-center text-gray-500">No jobs posted yet.</p>`;
    }
  } catch (err) {
    console.error(err);
  }
});
