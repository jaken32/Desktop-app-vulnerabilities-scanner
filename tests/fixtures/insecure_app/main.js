// DELIBERATELY-INSECURE Electron main process. Used only by the test suite to
// prove deskscanner detects each misconfiguration. Do not use as a template.
const { app, BrowserWindow, shell } = require('electron')
const path = require('path')

function createWindow () {
  const win = new BrowserWindow({
    width: 1024,
    height: 768,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
      webSecurity: false,
      allowRunningInsecureContent: true,
      enableRemoteModule: true,
      preload: path.join(__dirname, 'preload.js')
    }
  })
  // Loads remote content -> with nodeIntegration this is a full RCE path.
  win.loadURL('https://content.untrusted-cdn.net/app/index.html')
}

function openLink (target) {
  // Non-literal argument: attacker-controlled URL could use a dangerous scheme.
  shell.openExternal(target)
}

app.whenReady().then(createWindow)
module.exports = { openLink }
