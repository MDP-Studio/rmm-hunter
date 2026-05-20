const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("rmmHunter", {
  startScan: (options) => ipcRenderer.invoke("scan:start", options),
  selectKapeRoot: () => ipcRenderer.invoke("kape:selectRoot"),
  onProgress: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on("scan:progress", listener);
    return () => ipcRenderer.removeListener("scan:progress", listener);
  },
  onUpdateStatus: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on("updates:status", listener);
    return () => ipcRenderer.removeListener("updates:status", listener);
  },
  exportJson: (report) => ipcRenderer.invoke("report:exportJson", report),
  exportPdf: (report) => ipcRenderer.invoke("report:exportPdf", report),
  getAiSettings: () => ipcRenderer.invoke("ai:getSettings"),
  saveAiSettings: (settings) => ipcRenderer.invoke("ai:saveSettings", settings),
  clearAiKey: () => ipcRenderer.invoke("ai:clearKey"),
  explainReport: (report) => ipcRenderer.invoke("ai:explainReport", report),
  showPath: (targetPath) => ipcRenderer.invoke("path:show", targetPath),
  checkUpdates: () => ipcRenderer.invoke("updates:check"),
  downloadUpdate: () => ipcRenderer.invoke("updates:download"),
  installUpdate: () => ipcRenderer.invoke("updates:install"),
  openUpdate: (releaseUrl) => ipcRenderer.invoke("updates:openRelease", releaseUrl),
  openExternalLink: (url) => ipcRenderer.invoke("links:openExternal", url)
});
