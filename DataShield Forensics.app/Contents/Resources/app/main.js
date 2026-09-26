import { app, BrowserWindow, Menu } from 'electron';
import { fork } from 'child_process';
import path from 'path';
import fs from 'fs';
import http from 'http';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mainWindow = null;
let backendProcess = null;

const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;
const BACKEND_PORT = 5001;

// Logging helper
function logDiagnostic(msg) {
  const timestamp = new Date().toISOString();
  console.log(`[Electron Diagnostic ${timestamp}] ${msg}`);
}

/**
 * Starts the Express backend server child process automatically.
 */
function startBackendServer() {
  logDiagnostic(`App started. Mode: ${isDev ? 'DEVELOPMENT' : 'PRODUCTION'}`);

  let backendPath;
  let frontendDistPath;

  if (isDev) {
    backendPath = path.join(__dirname, 'backend', 'server.js');
    frontendDistPath = path.join(__dirname, 'frontend', 'dist');
  } else {
    const candidateAppDir = path.join(process.resourcesPath, 'app');
    const candidateAsarDir = path.join(process.resourcesPath, 'app.asar');

    if (fs.existsSync(path.join(candidateAppDir, 'backend', 'server.js'))) {
      backendPath = path.join(candidateAppDir, 'backend', 'server.js');
      frontendDistPath = path.join(candidateAppDir, 'frontend', 'dist');
    } else if (fs.existsSync(path.join(candidateAsarDir, 'backend', 'server.js'))) {
      backendPath = path.join(candidateAsarDir, 'backend', 'server.js');
      frontendDistPath = path.join(candidateAsarDir, 'frontend', 'dist');
    } else {
      backendPath = path.join(__dirname, 'backend', 'server.js');
      frontendDistPath = path.join(__dirname, 'frontend', 'dist');
    }
  }

  logDiagnostic(`Backend path resolved to: ${backendPath}`);
  logDiagnostic(`Frontend dist path resolved to: ${frontendDistPath}`);

  if (!fs.existsSync(backendPath)) {
    logDiagnostic(`[!] ERROR: Backend script not found at ${backendPath}`);
    return false;
  }

  const dbPath = isDev
    ? path.join(__dirname, 'backend', 'database', 'datashield_db.json')
    : path.join(app.getPath('userData'), 'datashield_db.json');

  const forkEnv = {
    ...process.env,
    PORT: BACKEND_PORT.toString(),
    NODE_ENV: isDev ? 'development' : 'production',
    FRONTEND_DIST: frontendDistPath,
    DB_PATH: dbPath
  };

  const forkOptions = {
    env: forkEnv,
    stdio: 'inherit'
  };

  if (!isDev) {
    forkOptions.execPath = process.execPath;
    forkEnv.ELECTRON_RUN_AS_NODE = '1';
  }

  try {
    backendProcess = fork(backendPath, [], forkOptions);

    logDiagnostic(`Backend process spawned with PID: ${backendProcess.pid}`);

    backendProcess.on('error', (err) => {
      logDiagnostic(`[!] Backend Process Error: ${err.message}`);
    });

    backendProcess.on('exit', (code, signal) => {
      logDiagnostic(`[!] Backend Process exited with code ${code}, signal ${signal}`);
    });

    return true;
  } catch (err) {
    logDiagnostic(`[!] Failed to spawn backend process: ${err.message}`);
    return false;
  }
}

/**
 * Polls backend GET /health until 200 OK is returned or max tries exceeded.
 */
function waitForBackendHealth(callback) {
  let tries = 0;
  const maxTries = 35; // 35 * 300ms = 10.5 seconds max wait

  logDiagnostic(`Initiating backend health check on http://localhost:${BACKEND_PORT}/health...`);

  const check = () => {
    tries++;
    const req = http.get(`http://localhost:${BACKEND_PORT}/health`, (res) => {
      if (res.statusCode === 200) {
        logDiagnostic(`Health check PASSED on try #${tries}! Backend is healthy.`);
        callback(true);
      } else if (tries < maxTries) {
        setTimeout(check, 300);
      } else {
        logDiagnostic(`[!] Health check FAILED after ${maxTries} tries. Status: ${res.statusCode}`);
        callback(false);
      }
    });

    req.on('error', (err) => {
      if (tries < maxTries) {
        setTimeout(check, 300);
      } else {
        logDiagnostic(`[!] Health check network error after ${maxTries} tries: ${err.message}`);
        callback(false);
      }
    });

    req.setTimeout(2000, () => {
      req.destroy();
    });
  };

  check();
}

/**
 * Generates an HTML error page to display if startup fails instead of a blank screen.
 */
function renderStartupErrorPage(win, errorDetails) {
  const errorHtml = `
  <!DOCTYPE html>
  <html>
  <head>
    <title>DataShield Forensics - Startup Diagnostic Error</title>
    <style>
      body { background-color: #0f172a; color: #f8fafc; font-family: system-ui, -apple-system, sans-serif; padding: 40px; margin: 0; }
      .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; max-width: 650px; margin: 0 auto; shadow: 0 10px 25px rgba(0,0,0,0.5); }
      h1 { color: #f87171; font-size: 20px; margin-top: 0; }
      p { font-size: 13px; color: #94a3b8; line-height: 1.6; }
      pre { background: #090d16; border: 1px solid #1e293b; padding: 12px; border-radius: 8px; color: #fbbf24; font-size: 11px; overflow-x: auto; }
      button { background: #2563eb; color: white; border: none; padding: 10px 18px; border-radius: 6px; font-weight: bold; cursor: pointer; margin-top: 15px; }
      button:hover { background: #1d4ed8; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>DataShield Forensics Backend Failed to Start</h1>
      <p>The desktop shell was unable to connect to the internal Express REST service on <strong>http://localhost:${BACKEND_PORT}</strong>.</p>
      <pre>${errorDetails}</pre>
      <button onclick="location.reload()">Retry Startup</button>
    </div>
  </body>
  </html>
  `;
  win.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(errorHtml)}`);
}

/**
 * Creates the main desktop application window.
 */
function createMainWindow(backendHealthy) {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    title: 'DataShield Forensics',
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#0f172a',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: false,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  // macOS App Menu
  const menuTemplate = [
    {
      label: 'DataShield Forensics',
      submenu: [
        { label: 'About DataShield Forensics', role: 'about' },
        { type: 'separator' },
        { label: 'Quit DataShield Forensics', role: 'quit' }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' }, { role: 'redo' }, { type: 'separator' },
        { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' }
      ]
    }
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(menuTemplate));

  if (!backendHealthy) {
    renderStartupErrorPage(mainWindow, `Backend health check failed on port ${BACKEND_PORT}.\nPlease verify node dependencies or check system port availability.`);
    return;
  }

  // Production and Dev load strategy
  const loadTargetUrl = `http://localhost:${BACKEND_PORT}`;
  logDiagnostic(`Loading primary application view from: ${loadTargetUrl}`);

  mainWindow.loadURL(loadTargetUrl).catch((err) => {
    logDiagnostic(`[!] Window loadURL error: ${err.message}`);
    renderStartupErrorPage(mainWindow, `Failed to load application URL ${loadTargetUrl}: ${err.message}`);
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// App Ready Event
app.whenReady().then(() => {
  const started = startBackendServer();
  if (!started) {
    createMainWindow(false);
    return;
  }

  waitForBackendHealth((isHealthy) => {
    createMainWindow(isHealthy);
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow(true);
    }
  });
});

// Clean termination of child backend process on exit
function cleanupAndQuit() {
  if (backendProcess) {
    logDiagnostic('Terminating backend child process cleanly...');
    backendProcess.kill('SIGTERM');
    backendProcess = null;
  }
}

app.on('before-quit', cleanupAndQuit);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
