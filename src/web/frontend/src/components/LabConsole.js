// A lab VM's screen in the browser (FR-04): noVNC 1.5.0 (MPL-2.0, https://github.com/novnc/noVNC)
// over the backend's console websocket, which only a signed-in admin can open
// (lab_routes.lab_console_socket). Loaded on demand from LabMachines, so noVNC stays out of the
// main bundle. Escape and every other key go to the VM, so the window closes from its button only.
import React, { useEffect, useRef, useState } from 'react';
import RFB from '@novnc/novnc';
import { getLabConsole, labConsoleUrl } from '../api';

const errorText = (err) => {
  const d = err.response?.data?.detail;
  if (!d) return err.message;
  return typeof d === 'string' ? d : JSON.stringify(d);
};

function LabConsole({ machine, onClose }) {
  const screenRef = useRef(null);
  const rfbRef = useRef(null);
  const [status, setStatus] = useState('Connecting…');
  const [connected, setConnected] = useState(false);
  const [scale, setScale] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      let info;
      try {
        info = await getLabConsole(machine.engine, machine.name);
      } catch (err) {
        if (!cancelled) setStatus(errorText(err));
        return;
      }
      if (cancelled || !screenRef.current) return;
      const password = info.password || '';
      const rfb = new RFB(screenRef.current, labConsoleUrl(machine.engine, machine.name), {
        credentials: password ? { password } : {},
        wsProtocols: ['binary'],
      });
      rfb.scaleViewport = true;
      rfb.resizeSession = false;
      rfb.focusOnClick = true;
      rfb.background = '#000';
      rfb.addEventListener('connect', () => {
        setConnected(true);
        setStatus(`Connected to ${machine.name}`);
        rfb.focus();
      });
      rfb.addEventListener('disconnect', (e) => {
        setConnected(false);
        setStatus(e.detail.clean ? 'Disconnected' : 'The console closed. The VM may have stopped, or the lab agent may need a restart.');
      });
      rfb.addEventListener('credentialsrequired', () => {
        if (password) rfb.sendCredentials({ password });
        else setStatus("The VM's VNC server asked for a password the lab doesn't have.");
      });
      rfb.addEventListener('securityfailure', (e) => setStatus(`Refused by the VM's VNC server: ${e.detail.reason || e.detail.status}`));
      rfb.addEventListener('desktopname', (e) => setStatus(`Connected to ${e.detail.name || machine.name}`));
      rfbRef.current = rfb;
    })();
    return () => {
      cancelled = true;
      if (rfbRef.current) rfbRef.current.disconnect();
      rfbRef.current = null;
    };
  }, [machine.engine, machine.name]);

  useEffect(() => {
    if (rfbRef.current) rfbRef.current.scaleViewport = scale;
  }, [scale]);

  return (
    <div className="mt-modal">
      <div className="mt-modal-box lab-console-box" role="dialog" aria-modal="true" aria-label={`Console of ${machine.name}`}>
        <div className="mt-modal-head">
          <strong>Console: {machine.name}</strong>
          <div className="mt-row lab-console-tools">
            <button className="mt-pill" disabled={!connected} title="Send Ctrl+Alt+Del to the VM"
                    onClick={() => rfbRef.current && rfbRef.current.sendCtrlAltDel()}>Ctrl+Alt+Del</button>
            <label className="lab-console-scale">
              <input type="checkbox" checked={scale} onChange={(e) => setScale(e.target.checked)} /> Fit to window
            </label>
            <button className="mt-close" onClick={onClose} aria-label="Close the console">×</button>
          </div>
        </div>
        <div className="lab-console-status mt-dim">{status}</div>
        <div className="lab-console-screen" ref={screenRef} />
      </div>
    </div>
  );
}

export default LabConsole;
