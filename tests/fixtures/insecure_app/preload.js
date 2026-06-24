// Insecure preload: exposes the raw ipcRenderer to the page, defeating the
// purpose of context isolation.
const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('api', ipcRenderer)
