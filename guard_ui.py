"""Standalone Callback Guard desktop interface (standard-library Tkinter)."""
import json
import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


def summary(report):
    av = report.get('antivirus', {}).get('status', 'Not completed')
    lines = [f"Result: {report.get('status', 'held')}", f'Defender: {av}']
    if report.get('error'):
        lines.append('Error: ' + report['error'])
    apk = report.get('apk')
    if apk:
        lines += ['', 'APK inspection', f"Package: {apk.get('package', 'Unknown')}",
                  f"Files: {apk['entry_count']} | Expanded: {apk['expanded_bytes'] / 1048576:.1f} MiB",
                  '', 'Requested permissions:']
        lines.extend('  ' + str(p) for p in apk.get('permissions', []))
        lines += ['', 'Coverage limitations:'] + ['  ' + item for item in apk.get('limitations', [])]
    lines += ['', 'Findings:']
    lines.extend(json.dumps(f, ensure_ascii=True) for f in report.get('findings', []))
    if not report.get('findings'):
        lines.append('None recorded. Check completion status above.')
    lines += ['', 'No software is installed or executed by this app.']
    return '\n'.join(lines)


def main():
    from guard import ROOT, run
    window = tk.Tk()
    icon = ROOT / 'CallbackInspector.ico'
    if icon.is_file():
        try:
            window.iconbitmap(str(icon))
        except tk.TclError:
            pass
    window.title('Callback Guard — File and APK Inspector')
    window.geometry('960x740')
    window.minsize(720, 540)
    frame = ttk.Frame(window, padding=18)
    frame.pack(fill='both', expand=True)
    header = ttk.Frame(frame)
    header.pack(fill='x', pady=(0, 14))
    logo = ROOT / 'CallbackInspector.png'
    if logo.is_file():
        try:
            logo_image = tk.PhotoImage(file=str(logo))
            logo_label = ttk.Label(header, image=logo_image)
            logo_label.image = logo_image  # Keep the Tk image alive while the UI is open.
            logo_label.pack(side='left', padx=(0, 14))
        except tk.TclError:
            pass
    header_text = ttk.Frame(header)
    header_text.pack(side='left', fill='x', expand=True)
    ttk.Label(header_text, text='Callback Guard', font=('Segoe UI', 22, 'bold')).pack(anchor='w')
    ttk.Label(header_text, text='Inspect a download or local file. APK mode is selected automatically.').pack(anchor='w', pady=(4, 0))
    ttk.Label(frame, text='HTTPS download or repository URL').pack(anchor='w')
    url = ttk.Entry(frame)
    url.pack(fill='x', pady=(3, 8))
    ttk.Label(frame, text='Optional download filename (use .apk for Android apps)').pack(anchor='w')
    name = ttk.Entry(frame)
    name.pack(fill='x', pady=(3, 10))
    controls = ttk.Frame(frame)
    controls.pack(fill='x')
    status = tk.StringVar(value='Ready. APK triage requires review; it does not certify app safety.')
    progress = ttk.Progressbar(frame, mode='indeterminate')
    progress.pack(fill='x', pady=(12, 5))
    ttk.Label(frame, textvariable=status, wraplength=880).pack(anchor='w', pady=(0, 8))
    notebook = ttk.Notebook(frame)
    notebook.pack(fill='both', expand=True)
    outputs = []
    for title in ('Summary', 'Full JSON report'):
        page = ttk.Frame(notebook)
        output = tk.Text(page, wrap='word', font=('Consolas', 10), state='disabled')
        scroll = ttk.Scrollbar(page, command=output.yview)
        output.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        output.pack(fill='both', expand=True)
        notebook.add(page, text=title)
        outputs.append(output)
    completed = queue.Queue()
    state = {'busy': False, 'report': None}

    def show(widget, text):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('end', text)
        widget.configure(state='disabled')

    def start(download=False):
        if state['busy']:
            return
        if download:
            if not url.get().strip():
                messagebox.showinfo('Download URL', 'Enter an HTTPS URL first.')
                return
            args = {'url': url.get().strip(), 'name': name.get().strip() or None}
        else:
            selected = filedialog.askopenfilename(title='Choose a file to inspect', filetypes=[('All files', '*.*'), ('Android APK', '*.apk')])
            if not selected:
                return
            args = {'source': selected}
        state.update(busy=True, report=None)
        for button in scan_buttons:
            button.configure(state='disabled')
        report_button.configure(state='disabled')
        for output in outputs:
            show(output, '')
        status.set('Scanning… Defender and static inspection may take several minutes.')
        progress.start()

        def worker():
            try:
                completed.put(('result', run(**args)))
            except Exception as exc:
                completed.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True).start()
        window.after(100, poll)

    def poll():
        try:
            kind, value = completed.get_nowait()
        except queue.Empty:
            window.after(100, poll)
            return
        progress.stop()
        state['busy'] = False
        for button in scan_buttons:
            button.configure(state='normal')
        if kind == 'error':
            status.set('Scan failed; no approval issued.')
            show(outputs[0], value)
            return
        report, path = value
        state['report'] = path
        report_button.configure(state='normal')
        status.set(f"{report['status'].upper()} — Report saved: {path.name}")
        show(outputs[0], summary(report) + '\n\nReport: ' + str(path))
        show(outputs[1], json.dumps(report, indent=2, ensure_ascii=True))

    scan_buttons = [ttk.Button(controls, text='Scan download', command=lambda: start(True)),
                    ttk.Button(controls, text='Choose local file / APK', command=start)]
    for button in scan_buttons:
        button.pack(side='left', padx=(0, 8))
    report_button = ttk.Button(controls, text='Open report folder', state='disabled', command=lambda: os.startfile(str(state['report'].parent)))
    report_button.pack(side='left', padx=(0, 8))
    ttk.Button(controls, text='Scan history', command=lambda: os.startfile(str(ROOT / 'intake'))).pack(side='left')

    def close():
        if state['busy']:
            messagebox.showinfo('Scan in progress', 'Please wait for this scan to finish before closing.')
        else:
            window.destroy()
    window.protocol('WM_DELETE_WINDOW', close)
    window.mainloop()


if __name__ == '__main__':
    main()
