const authView = document.querySelector("#auth-view");
const dashboard = document.querySelector("#dashboard");
const toast = document.querySelector("#toast");
let csrfToken = "";
let toastTimer;

async function api(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body && !(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch(url, { credentials: "same-origin", ...options, headers });
  const payload = response.status === 204 ? {} : await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `请求失败 (${response.status})`);
  return payload;
}

function notify(message, error = false) {
  toast.textContent = message;
  toast.classList.toggle("error-toast", error);
  toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("visible"), 3600);
}

function showAuth(setupRequired) {
  authView.hidden = false;
  dashboard.hidden = true;
  document.querySelector("#auth-title").textContent = setupRequired ? "设置管理员" : "管理员登录";
  document.querySelector("#auth-description").textContent = setupRequired
    ? "首次使用请设置一个至少 12 位的管理员密码。初始化令牌会显示在启动服务的终端中。"
    : "登录后管理本机 OpenVPN 服务端。";
  document.querySelector("#setup-token-wrap").hidden = !setupRequired;
  document.querySelector("#setup-token").required = setupRequired;
  document.querySelector("#password").autocomplete = setupRequired ? "new-password" : "current-password";
  document.querySelector("#auth-submit").textContent = setupRequired ? "完成初始化" : "登录";
  document.querySelector("#auth-error").textContent = "";
  document.querySelector("#auth-form").dataset.setup = String(setupRequired);
}

async function showDashboard() {
  authView.hidden = true;
  dashboard.hidden = false;
  await Promise.all([loadConfig(), loadProfiles(), loadService()]);
}

async function boot() {
  const state = await api("/api/session");
  csrfToken = state.csrf_token || "";
  if (state.authenticated) await showDashboard();
  else showAuth(state.setup_required);
}

document.querySelector("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const password = document.querySelector("#password").value;
  const body = form.dataset.setup === "true"
    ? { password, setup_token: document.querySelector("#setup-token").value.trim() }
    : { password };
  try {
    const result = await api(form.dataset.setup === "true" ? "/api/setup" : "/api/login", {
      method: "POST",
      body: JSON.stringify(body),
    });
    csrfToken = result.csrf_token;
    await showDashboard();
  } catch (error) {
    document.querySelector("#auth-error").textContent = error.message;
  }
});

document.querySelector("#logout").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST" });
    csrfToken = "";
    showAuth(false);
  } catch (error) {
    notify(error.message, true);
  }
});

async function loadConfig() {
  try {
    const data = await api("/api/config");
    const form = document.querySelector("#config-form");
    for (const [key, value] of Object.entries(data.config)) {
      const field = form.elements.namedItem(key);
      if (field) field.value = Array.isArray(value) ? value.join(", ") : value;
    }
    document.querySelector("#config-path").textContent = `写入：${data.config_path}`;
    document.querySelector("#service-config-path").textContent = data.config_path;
    document.querySelector("#generated-config").textContent = data.generated_config;
  } catch (error) {
    notify(error.message, true);
  }
}

document.querySelector("#config-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const config = Object.fromEntries(form.entries());
  for (const key of ["port", "keepalive_interval", "keepalive_timeout", "max_clients"]) {
    config[key] = Number(config[key]);
  }
  config.dns = config.dns.split(",").map((address) => address.trim()).filter(Boolean);
  try {
    const result = await api("/api/config", { method: "PUT", body: JSON.stringify(config) });
    document.querySelector("#generated-config").textContent = result.generated_config;
    notify("配置已保存并生成");
  } catch (error) {
    notify(error.message, true);
  }
});

async function loadProfiles() {
  try {
    const data = await api("/api/profiles");
    document.querySelector("#profile-count").textContent = `${data.profiles.length} 个配置`;
    const list = document.querySelector("#profiles-list");
    list.replaceChildren();
    if (!data.profiles.length) {
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = "还没有导入客户端配置";
      list.append(empty);
      return;
    }
    for (const profile of data.profiles) {
      const row = document.createElement("article");
      row.className = "profile-row";
      const description = document.createElement("div");
      const name = document.createElement("strong");
      name.textContent = profile.name;
      const size = document.createElement("span");
      size.textContent = `${(profile.bytes / 1024).toFixed(1)} KB`;
      description.append(name, size);
      const actions = document.createElement("div");
      actions.className = "row-actions";
      const download = document.createElement("a");
      download.className = "button secondary compact";
      download.href = `/api/profiles/${encodeURIComponent(profile.id)}/download`;
      download.textContent = "下载";
      const remove = document.createElement("button");
      remove.className = "button quiet compact";
      remove.type = "button";
      remove.textContent = "移除";
      remove.addEventListener("click", async () => {
        if (!confirm(`确定移除 ${profile.name}？`)) return;
        try {
          await api(`/api/profiles/${encodeURIComponent(profile.id)}`, { method: "DELETE" });
          notify("客户端配置已移除");
          await loadProfiles();
        } catch (error) {
          notify(error.message, true);
        }
      });
      actions.append(download, remove);
      row.append(description, actions);
      list.append(row);
    }
  } catch (error) {
    notify(error.message, true);
  }
}

document.querySelector("#generate-profile-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const result = await api("/api/profiles/generate", {
      method: "POST",
      body: JSON.stringify({
        name: form.elements.name.value.trim(),
        remote: form.elements.remote.value.trim(),
      }),
    });
    form.reset();
    notify(`客户端 ${result.name} 已签发，可在列表中下载配置`);
    await loadProfiles();
  } catch (error) {
    notify(error.message, true);
  } finally {
    submit.disabled = false;
  }
});

document.querySelector("#profile-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const file = document.querySelector("#profile-file").files[0];
  if (!file || !file.name.toLowerCase().endsWith(".ovpn")) {
    notify("请选择 .ovpn 文件", true);
    return;
  }
  if (file.size > 1024 * 1024) {
    notify("文件不能超过 1 MiB", true);
    return;
  }
  try {
    await api("/api/profiles", {
      method: "POST",
      body: JSON.stringify({ name: form.elements.name.value, content: await file.text() }),
    });
    form.reset();
    notify("客户端配置已安全导入");
    await loadProfiles();
  } catch (error) {
    notify(error.message, true);
  }
});

async function loadService() {
  try {
    const status = await api("/api/service");
    const value = document.querySelector("#service-status");
    value.classList.toggle("is-active", status.active);
    value.classList.toggle("is-inactive", !status.active);
    value.innerHTML = `<i class="status-dot"></i>${status.active ? "运行中" : status.configured ? "未运行" : "未配置"}`;
    document.querySelector("#service-detail").textContent = status.message || "";
    document.querySelector("#service-unit").textContent = status.unit || "未配置";
  } catch (error) {
    notify(error.message, true);
  }
}

document.querySelector("#refresh-service").addEventListener("click", loadService);
document.querySelectorAll(".service-action").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      const result = await api(`/api/service/${button.dataset.action}`, { method: "POST" });
      notify(result.message || "服务操作已完成");
      await loadService();
    } catch (error) {
      notify(error.message, true);
    }
  });
});

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab === button));
    for (const tab of ["server", "clients", "service"]) {
      document.querySelector(`#tab-${tab}`).hidden = button.dataset.tab !== tab;
    }
  });
});

boot().catch((error) => {
  showAuth(false);
  document.querySelector("#auth-error").textContent = error.message;
});
