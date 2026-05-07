const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("rmmHunter", {
  startScan: () => ipcRenderer.invoke("scan:start"),
  onProgress: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on("scan:progress", listener);
    return () => ipcRenderer.removeListener("scan:progress", listener);
  },
  exportJson: (report) => ipcRenderer.invoke("report:exportJson", report),
  exportPdf: (report) => ipcRenderer.invoke("report:exportPdf", report),
  explainReport: (report) => ipcRenderer.invoke("ai:explainReport", report),
  showPath: (targetPath) => ipcRenderer.invoke("path:show", targetPath)
});
