/* ============================================================
   history.js -- history/download controller
   ============================================================ */

(function () {
  "use strict";

  if (!requireAuth()) return;

  var historyTbody = document.getElementById("history-tbody");
  var refreshBtn = document.getElementById("refresh-history-btn");
  var logoutBtn = document.getElementById("logout-btn");
  var headerUser = document.getElementById("header-user");

  var modalOverlay = document.getElementById("download-modal-overlay");
  var modalTitle = document.getElementById("download-modal-title");
  var formatSelect = document.getElementById("download-format");
  var recipientEmailInput = document.getElementById("download-email");
  var closeModalBtn = document.getElementById("download-modal-cancel");
  var downloadNowBtn = document.getElementById("download-now-btn");
  var sendEmailBtn = document.getElementById("send-email-btn");

  var selectedOrg = null;

  function formatScanTypeLabel(scanType) {
    return scanType === "domain"
      ? "Domain (Subdomains only)"
      : "Extended (Subdomains + Ports + Live)";
  }

  function init() {
    var token = getToken();
    if (token) {
      var payload = decodeJWT(token);
      if (payload && payload.sub) {
        headerUser.textContent = payload.sub;
        recipientEmailInput.value = payload.sub;
      }
    }

    refreshBtn.addEventListener("click", loadHistory);
    logoutBtn.addEventListener("click", logout);

    closeModalBtn.addEventListener("click", closeModal);
    modalOverlay.addEventListener("click", function (e) {
      if (e.target === modalOverlay) {
        closeModal();
      }
    });
    downloadNowBtn.addEventListener("click", downloadSelected);
    sendEmailBtn.addEventListener("click", sendSelectedByEmail);

    loadHistory();
  }

  function openModal(orgname) {
    selectedOrg = orgname;
    modalTitle.textContent = "Download / Email Report - " + orgname;
    modalOverlay.classList.add("active");
  }

  function closeModal() {
    selectedOrg = null;
    modalOverlay.classList.remove("active");
  }

  async function downloadSelected() {
    if (!selectedOrg) return;
    var fmt = formatSelect.value;
    var url =
      API.downloadRecon +
      "/" +
      encodeURIComponent(selectedOrg) +
      "/download?format=" +
      encodeURIComponent(fmt);
    try {
      await downloadAuthenticatedFile(url, selectedOrg + "." + fmt);
      showToast("success", "Download Started", "Report downloaded successfully.");
    } catch (err) {
      showToast("error", "Download Failed", err.message);
    }
  }

  async function sendSelectedByEmail() {
    if (!selectedOrg) return;
    var fmt = formatSelect.value;
    var recipientEmail = recipientEmailInput.value.trim();
    if (!recipientEmail) {
      showToast("error", "Validation Error", "Recipient email is required.");
      return;
    }

    sendEmailBtn.disabled = true;
    sendEmailBtn.textContent = "Sending...";

    try {
      var response = await apiFetch(
        API.sendReconEmail + "/" + encodeURIComponent(selectedOrg) + "/send-email",
        {
          method: "POST",
          body: JSON.stringify({
            recipient_email: recipientEmail,
            format: fmt,
          }),
        }
      );
      if (!response.ok) {
        var errData = await response.json().catch(function () {
          return {};
        });
        throw new Error(errData.detail || "Email send failed");
      }

      showToast("success", "Email Sent", "Report sent to " + recipientEmail);
      closeModal();
    } catch (err) {
      showToast("error", "Email Failed", err.message);
    } finally {
      sendEmailBtn.disabled = false;
      sendEmailBtn.textContent = "Send Email";
    }
  }

  async function loadHistory() {
    try {
      var response = await apiFetch(API.allRecon, { method: "GET" });
      if (!response.ok) {
        throw new Error("Could not load history");
      }
      var data = await response.json();
      var records = Array.isArray(data) ? data : [];
      records.sort(function (a, b) {
        return new Date(b.started_at || 0) - new Date(a.started_at || 0);
      });
      renderHistory(records);
    } catch (err) {
      showToast("error", "Load Failed", err.message || "Unable to fetch history.");
    }
  }

  function renderHistory(records) {
    if (!records.length) {
      historyTbody.innerHTML =
        '<tr id="history-empty"><td colspan="7"><div class="empty-state"><p>No scan history found yet.</p></div></td></tr>';
      return;
    }

    historyTbody.innerHTML = "";

    records.forEach(function (record) {
      var tr = document.createElement("tr");
      tr.innerHTML =
        "<td><strong>" +
        escapeHTML(record.orgname || "--") +
        "</strong></td>" +
        "<td>" +
        escapeHTML(formatScanTypeLabel(record.scan_type || "extended")) +
        "</td>" +
        "<td>" +
        domainChips(record.domains || []) +
        "</td>" +
        "<td>" +
        escapeHTML(record.initiated_by || "--") +
        "</td>" +
        "<td>" +
        formatDate(record.started_at) +
        "</td>" +
        "<td>" +
        statusBadge(record.status) +
        "</td>" +
        '<td><div class="actions-cell">' +
        '<a href="./details.html?org=' +
        encodeURIComponent(record.orgname || "") +
        '" class="btn btn-secondary btn-sm">View</a>' +
        '<button class="btn btn-secondary btn-sm btn-download">Download</button>' +
        '<button class="btn btn-destructive btn-sm btn-delete">Delete</button>' +
        "</div></td>";

      tr.querySelector(".btn-download").addEventListener("click", function () {
        openModal(record.orgname);
      });
      tr.querySelector(".btn-delete").addEventListener("click", function () {
        handleDelete(record.orgname);
      });

      historyTbody.appendChild(tr);
    });
  }

  async function handleDelete(orgname) {
    var confirmed = await showConfirmModal(
      "Delete Recon Data",
      'Delete all records and files for "' + orgname + '"?',
      "Delete"
    );
    if (!confirmed) return;

    try {
      var response = await apiFetch(API.deleteRecon + "/" + encodeURIComponent(orgname), {
        method: "DELETE",
      });
      if (!response.ok) {
        var errData = await response.json().catch(function () {
          return {};
        });
        throw new Error(errData.detail || "Delete failed");
      }
      showToast("success", "Deleted", "Recon data removed for " + orgname);
      loadHistory();
    } catch (err) {
      showToast("error", "Delete Failed", err.message);
    }
  }

  init();
})();
