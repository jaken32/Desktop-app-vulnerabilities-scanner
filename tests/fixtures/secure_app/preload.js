// Secure preload: exposes a small, explicit API rather than the raw bridge.
const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('api', {
  ping: () => ipcRenderer.invoke('ping')
})
