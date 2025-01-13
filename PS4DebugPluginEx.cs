using System;
using System.Drawing;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Reflection;
using System.Text;
using System.Threading;
using ReClassNET.Core;
using ReClassNET.Debugger;
using ReClassNET.Forms;
using ReClassNET.Memory;
using ReClassNET.Plugins;
using ReClassNET.UI;
using ReClassNET.Util;

using libdebug;
using static libdebug.PS4DBG;

// The namespace name must equal the plugin name
namespace PS4DebugPlugin
{
    class IniFile   // revision 11
    {
        string Path;
        string EXE = Assembly.GetExecutingAssembly().GetName().Name;

        [DllImport("kernel32", CharSet = CharSet.Unicode)]
        static extern long WritePrivateProfileString(string Section, string Key, string Value, string FilePath);

        [DllImport("kernel32", CharSet = CharSet.Unicode)]
        static extern int GetPrivateProfileString(string Section, string Key, string Default, StringBuilder RetVal, int Size, string FilePath);

        public IniFile(string IniPath = null)
        {
            Path = new FileInfo(IniPath ?? EXE + ".ini").FullName;
        }

        public string Read(string Key, string Section = null)
        {
            var RetVal = new StringBuilder(255);
            GetPrivateProfileString(Section ?? EXE, Key, "", RetVal, 255, Path);
            return RetVal.ToString();
        }

        public Boolean ReadBoolean(string Key, string Section = null)
        {
            return Read(Key, Section) == "True";
        }

        public void Write(string Key, string Value, string Section = null)
        {
            WritePrivateProfileString(Section ?? EXE, Key, Value, Path);
        }

        public void Write(string Key, Boolean Value, string Section = null)
        {
            WritePrivateProfileString(Section ?? EXE, Key, Value ? "True" : "False", Path);
        }

        public void DeleteKey(string Key, string Section = null)
        {
            Write(Key, null, Section ?? EXE);
        }

        public void DeleteSection(string Section = null)
        {
            Write(null, null, Section ?? EXE);
        }

        public bool KeyExists(string Key, string Section = null)
        {
            return Read(Key, Section).Length > 0;
        }
    }

    /// <summary>The class name must equal the namespace name + "Ext"</summary>
    public class PS4DebugPluginExt : Plugin, ICoreProcessFunctions
    {
        private const string SettingsFile = "PS4.ini";
        private const string DEFAULT_IP = "192.168.2.1";
        private const int DEFAULT_DefaultPlugin = 0;
        private const Boolean DEFAULT_DisableSectionsAndModules = true;
        private const Boolean DEFAULT_ShowKernelBaseAddress = false;
        private const string iniSection = "PS4";
        private const string iniIP = "IP";
        private const string iniDefaultPlugin = "DefaultPlugin";
        private const string iniDisableSectionsAndModules = "DisableSectionsAndModules";
        private const string iniShowKernelBaseAddress = "ShowKernelBaseAddress";

        private readonly object sync = new object();
        private IPluginHost host;
        private string IP;
        private int DefaultPlugin;
        private Boolean DisableSectionsAndModules;
        private Boolean ShowKernelBaseAddress;
        private static AutoResetEvent areDebugEvent = new AutoResetEvent(false);
        private static uint ExceptionCode;
        private static regs Registers;
        private static dbregs DebugRegisters;

        private ulong KernelBase { get; set; }

		/// <summary>The icon to display in the plugin manager form.</summary>
        public override Image Icon => Properties.Resources.icon;

        private PS4DBG ps4 { get; set; }

        private void tbIP_KeyUp(object sender, KeyEventArgs e)
        {
            TextBox textBox = (TextBox)sender;
            IP = textBox.Text;
        }

        private void cbDefaultPluginSelectedIndexChanged(object sender, EventArgs e)
        {
            ComboBox comboBox = (ComboBox)sender;
            DefaultPlugin = comboBox.SelectedIndex;
        }

        private void chkDisableSectionsAndModulesCheckedChanged(object sender, EventArgs e)
        {
            CheckBox checkBox = (CheckBox)sender;
            DisableSectionsAndModules = checkBox.Checked;
        }

        private void chkShowKernelBaseAddressCheckedChanged(object sender, EventArgs e)
        {
            CheckBox checkBox = (CheckBox)sender;
            ShowKernelBaseAddress = checkBox.Checked;
        }

        /// <summary>
        /// This method gets called when a new windows is opened.
        /// You can use this function to add a settings panel into the settings dialog for example.
        /// </summary>
        private void OnWindowAdded(object sender, GlobalWindowManagerEventArgs e)
		{
			if (e.Form is SettingsForm settingsForm)
			{
				settingsForm.Shown += delegate (object sender2, EventArgs e2)
				{
					try
					{
						var settingsTabControl = settingsForm.Controls.Find("settingsTabControl", true).FirstOrDefault() as TabControl;
                        if (settingsTabControl != null)
                        {
                            var PS4Tab = settingsTabControl.Controls.Find("tabPS4", true).FirstOrDefault() as TabPage;
                            if (PS4Tab == null)
                            {
                                var newTab = new TabPage("PS4")
                                {
                                    Name = "tabPS4",
                                    UseVisualStyleBackColor = true
                                };

                                // IP
                                var lblIP = new Label()
                                {
                                    Name = "lblIP",
                                    Text = "IP:",
                                    AutoSize = true,
                                    Location = new System.Drawing.Point(6, 6),
                                    Size = new System.Drawing.Size(28, 13),
                                };
                                newTab.Controls.Add(lblIP);

                                var tbIP = new TextBox()
                                {
                                    Name = "tbIP",
                                    Text = IP,
                                    Location = new System.Drawing.Point(98, 3),
                                    Size = new System.Drawing.Size(120, 20)
                                };
                                tbIP.KeyUp += tbIP_KeyUp;
                                newTab.Controls.Add(tbIP);

                                // DefaultPlugin
                                var lblDefaultPlugin = new Label()
                                {
                                    Name = "lblDefaultPlugin",
                                    Text = "Default Plugin:",
                                    AutoSize = true,
                                    Location = new System.Drawing.Point(6, 30),
                                    Size = new System.Drawing.Size(28, 13),
                                };
                                newTab.Controls.Add(lblDefaultPlugin);

                                var cbDefaultPlugin = new ComboBox()
                                {
                                    Name = "cbDefaultPlugin",
                                    Location = new System.Drawing.Point(98, 27),
                                    Size = new System.Drawing.Size(120, 20),
                                };
                                cbDefaultPlugin.Items.Add("None");
                                cbDefaultPlugin.Items.Add("Frame4");
                                cbDefaultPlugin.Items.Add("PS4Debug");
                                cbDefaultPlugin.SelectedIndex = DefaultPlugin;
                                cbDefaultPlugin.SelectedIndexChanged += cbDefaultPluginSelectedIndexChanged;
                                newTab.Controls.Add(cbDefaultPlugin);

                                // DisableSectionsAndModules
                                var chkDisableSectionsAndModules = new CheckBox()
                                {
                                    Name = "chkDisableSectionsAndModules",
                                    Text = "Disable Sections and Modules (Reduce Bandwidth)",
                                    Checked = DisableSectionsAndModules,
                                    AutoSize = true,
                                    Location = new System.Drawing.Point(6, 52),
                                    Size = new System.Drawing.Size(28, 13),
                                };
                                chkDisableSectionsAndModules.CheckedChanged += chkDisableSectionsAndModulesCheckedChanged;
                                newTab.Controls.Add(chkDisableSectionsAndModules);

                                // ShowKernelBaseAddress
                                var chkShowKernelBaseAddress = new CheckBox()
                                {
                                    Name = "chkShowKernelBaseAddress",
                                    Text = "Show Kernel BaseAddress [Requires Restart]",
                                    Checked = ShowKernelBaseAddress,
                                    AutoSize = true,
                                    Location = new System.Drawing.Point(6, 72),
                                    Size = new System.Drawing.Size(28, 13),
                                };
                                chkShowKernelBaseAddress.CheckedChanged += chkShowKernelBaseAddressCheckedChanged;
                                newTab.Controls.Add(chkShowKernelBaseAddress);

                                settingsTabControl.TabPages.Add(newTab);
                            } else
                            {
                                var tbIP = PS4Tab.Controls.Find("tbIP", true).FirstOrDefault() as TextBox;
                                if (tbIP != null)
                                    tbIP.KeyUp += tbIP_KeyUp;

                                var cbDefaultPlugin = PS4Tab.Controls.Find("cbDefaultPlugin", true).FirstOrDefault() as ComboBox;
                                if (cbDefaultPlugin != null)
                                    cbDefaultPlugin.SelectedIndexChanged += cbDefaultPluginSelectedIndexChanged;

                                var chkDisableSectionsAndModules = PS4Tab.Controls.Find("chkDisableSectionsAndModules", true).FirstOrDefault() as CheckBox;
                                if (chkDisableSectionsAndModules != null)
                                    chkDisableSectionsAndModules.CheckedChanged += chkDisableSectionsAndModulesCheckedChanged;

                                var chkShowKernelBaseAddress = PS4Tab.Controls.Find("chkShowKernelBaseAddress", true).FirstOrDefault() as CheckBox;
                                if (chkShowKernelBaseAddress != null)
                                    chkShowKernelBaseAddress.CheckedChanged += chkShowKernelBaseAddressCheckedChanged;
                            }
                        }
					}
					catch
					{

					}
				};
			}
		}

        /// <summary>This method gets called when ReClass.NET loads the plugin.</summary>
        public override bool Initialize(IPluginHost host)
        {
            Contract.Requires(host != null);

            this.host = host ?? throw new ArgumentNullException(nameof(host));

            // Notfiy the plugin if a window is shown.
            GlobalWindowManager.WindowAdded += OnWindowAdded;

            try
            {
                var path = Path.Combine(PathUtil.SettingsFolderPath, SettingsFile);
                var ini = new IniFile(path);
                IP = ini.Read(iniIP, iniSection);
                if (IP == "") { IP = DEFAULT_IP; }

                var tmp = ini.Read(iniDefaultPlugin, iniSection);
                if (tmp == "")
                    DefaultPlugin = DEFAULT_DefaultPlugin;
                else
                    DefaultPlugin = Int32.Parse(tmp);

                tmp = ini.Read(iniDisableSectionsAndModules, iniSection);
                if (tmp == "")
                    DisableSectionsAndModules = DEFAULT_DisableSectionsAndModules;
                else
                    DisableSectionsAndModules = (tmp == "True");

                tmp = ini.Read(iniShowKernelBaseAddress, iniSection);
                if (tmp == "")
                    ShowKernelBaseAddress = DEFAULT_DisableSectionsAndModules;
                else
                    ShowKernelBaseAddress = (tmp == "True");
            }
            catch // (Exception ex)
            {
                IP = DEFAULT_IP;
                DefaultPlugin = DEFAULT_DefaultPlugin;
                DisableSectionsAndModules = DEFAULT_DisableSectionsAndModules;
                ShowKernelBaseAddress = DEFAULT_ShowKernelBaseAddress;
//                host.Logger.Log(ex);
            }

            KernelBase = 0;
            ps4 = null;

            host.Process.CoreFunctions.RegisterFunctions("PS4DBG Loader", this);

            if (DefaultPlugin == 2) {
                host.Process.CoreFunctions.SetActiveFunctionsProvider("PS4DBG Loader");
            }

            if (ShowKernelBaseAddress) 
                CreateObjects();

            return true;
		}

        public void CreateObjects()
        {
            foreach (var Window in GlobalWindowManager.Windows)
            {
                try
                {
                    var mainMenuStrip = Window.Controls.Find("mainMenuStrip", true).FirstOrDefault() as MenuStrip;
                    if(mainMenuStrip != null)
                    {
                        var tbKernelBaseAddress = mainMenuStrip.Items.Find("tbKernelBaseAddress", true).FirstOrDefault() as ToolStripTextBox;
                        if (tbKernelBaseAddress == null)
                        {
                            tbKernelBaseAddress = new ToolStripTextBox()
                            {
                                Name = "tbKernelBaseAddress",
                                Text = "0x0000000000000000",
//                                AutoSize = true,
                                Size = new System.Drawing.Size(114, 13),
                            };
                            mainMenuStrip.Items.Add(tbKernelBaseAddress);
                        }

/*
                        var newButton = new ToolStripButton()
                        {
                            Name = "GetBaseAddressBtn",
                            Text = "Get Base"
                        };
                        newButton.Click += (object sender, EventArgs args) => {
                            MemoryEntry mainExecutable;
                            if (ps4 == null)
                            {
                                return;
                            }

                            mainExecutable = ps4.GetProcessMaps(ProcessId).entries.ToList().Find(e => e.name == "executable");
                            if (mainExecutable != null)
                            {
                                newMenuTextBox.Text = $"0x{mainExecutable.start.ToString("X")}";
                            }
                        };
                        mainMenuStrip.Items.Add(newButton);
*/
                    break;
                    }
                }
                catch (Exception ex)
                {
                    host.Logger.Log(ex);
                }
            }
        }

        /// <summary>This method gets called when ReClass.NET unloads the plugin.</summary>
        public override void Terminate()
		{
            Disconnect();

            GlobalWindowManager.WindowAdded -= OnWindowAdded;

            // Save
            var path = Path.Combine(PathUtil.SettingsFolderPath, SettingsFile);
            var ini = new IniFile(path);
            ini.Write(iniIP, IP, iniSection);
            ini.Write(iniDefaultPlugin, DefaultPlugin.ToString(), iniSection);
            ini.Write(iniDisableSectionsAndModules, DisableSectionsAndModules, iniSection);
            ini.Write(iniShowKernelBaseAddress, ShowKernelBaseAddress, iniSection);

            host = null;
		}

        public void Connect()
        {
            if (ps4 != null)
            {
                if (ps4.IsConnected) { return; }
                ps4 = null;
            }

            ps4 = new PS4DBG(IP);
            ps4.Connect();
/*
            try
            {
                ps4 = new PS4DBG(IP);
                ps4.Connect();
            }
            catch (Exception ex)
            {
                ps4 = null;
                host.Logger.Log(ex);
            }
*/
            KernelBase = ps4.KernelBase();
            // Display KernelBase
            foreach (var Window in GlobalWindowManager.Windows)
            {
                var mainMenuStrip = Window.Controls.Find("mainMenuStrip", true).FirstOrDefault() as MenuStrip;
                if (mainMenuStrip != null)
                {
                    var tbKernelBaseAddress = mainMenuStrip.Items.Find("tbKernelBaseAddress", true).FirstOrDefault() as ToolStripTextBox;
                    if (tbKernelBaseAddress != null)
                    {
                        tbKernelBaseAddress.Text = $"0x{KernelBase.ToString("X")}";
                    }
                    break;
                }
            }
        }

        public void Disconnect()
        {
            lock (sync)
            {
                KernelBase = 0;

                if (ps4 != null)
                {
                    if (ps4.IsDebugging)
                        ps4.DetachDebugger();
                    if (ps4.IsConnected)
                        ps4.Disconnect();

                    ps4 = null;
                }
            }
        }

        public void EnumerateProcesses(EnumerateProcessCallback callbackProcess)
        {
            if (callbackProcess == null)
            {
                return;
            }

            Connect();

            if (ps4 == null) { return; }
            var ProcessList = ps4.GetProcessList().processes.ToList();
            foreach (var Process in ProcessList) 
            {
                EnumerateProcessData ProcessData = new EnumerateProcessData()
                {
                    Id = (IntPtr)Process.pid,
                    Name = Process.name,
                    Path = Process.name
                };

                callbackProcess(ref ProcessData);
            }
        }
        SectionProtection GetProtectionLevel(uint prot)
        {
            SectionProtection sectionProtection = new SectionProtection();

            if ((prot & (uint)VM_PROTECTIONS.VM_PROT_READ) == (uint)VM_PROTECTIONS.VM_PROT_READ)
                sectionProtection |= SectionProtection.Read;

            if ((prot & (uint)VM_PROTECTIONS.VM_PROT_WRITE) == (uint)VM_PROTECTIONS.VM_PROT_WRITE)
                sectionProtection |= SectionProtection.Read | SectionProtection.Write;

            if ((prot & (uint)VM_PROTECTIONS.VM_PROT_DEFAULT) == (uint)VM_PROTECTIONS.VM_PROT_DEFAULT)
                sectionProtection |= SectionProtection.Read | SectionProtection.Write;

            if ((prot & (uint)VM_PROTECTIONS.VM_PROT_EXECUTE) == (uint)VM_PROTECTIONS.VM_PROT_EXECUTE)
                sectionProtection |= SectionProtection.Execute;

            if ((prot & (uint)VM_PROTECTIONS.VM_PROT_READEXEC) == (uint)VM_PROTECTIONS.VM_PROT_READEXEC)
                sectionProtection |= SectionProtection.Read | SectionProtection.Execute;

            if ((prot & (uint)VM_PROTECTIONS.VM_PROT_ALL) == (uint)VM_PROTECTIONS.VM_PROT_ALL)
                sectionProtection |= SectionProtection.Execute | SectionProtection.Read | SectionProtection.Write;

            return sectionProtection;
        }

        public void EnumerateRemoteSectionsAndModules(IntPtr process, EnumerateRemoteSectionCallback callbackSection, EnumerateRemoteModuleCallback callbackModule)
        {
            if (DisableSectionsAndModules) { return; }
            if (ps4 == null) { return; }

            lock (sync)
            {
                try
                {
                    var ProcessMap = ps4.GetProcessMaps(process.ToInt32()).entries;
                    foreach (var map in ProcessMap)
                    {
                        if (map.name.Length == 0)
                            continue;

                        EnumerateRemoteModuleData ModuleData = new EnumerateRemoteModuleData()
                        {
                            BaseAddress = (IntPtr)map.start,
                            Size = (IntPtr)(map.end - map.start),
                            Path = map.name
                        };

                        callbackModule(ref ModuleData);

                        EnumerateRemoteSectionData SectionData = new EnumerateRemoteSectionData()
                        {
                            BaseAddress = (IntPtr)map.start,
                            ModulePath = map.name,
                            Size = (IntPtr)(map.end - map.start),
                            Category = SectionCategory.DATA,
                            Protection = GetProtectionLevel(map.prot),
                            Name = map.name,
                            Type = SectionType.Image
                        };

                        callbackSection(ref SectionData);
                    }
                }
                catch (Exception ex)
                {
                    host.Logger.Log(ex);
                    throw new Exception("Failed to enumerate process list:" + ex.ToString());
                }
            }
        }

        public IntPtr OpenRemoteProcess(IntPtr pid, ProcessAccess desiredAccess)
        {
            if (ps4 == null) { return IntPtr.Zero; }

            lock (sync)
            {
                try
                {
                    var ProcessMap = ps4.GetProcessMaps(pid.ToInt32());
                    if (ProcessMap.entries.Length == 0)
                        return IntPtr.Zero;
                }
                catch (Exception ex)
                {
                    host.Logger.Log(ex);
                }
            }
            return (IntPtr)pid;
        }

        public bool IsProcessValid(IntPtr process)
        {
            if (ps4 == null) { return false; }

            lock (sync)
            {
                return (process.ToInt32() != -1 && (ps4 != null) && ps4.IsConnected);
            }
        }

        public void CloseRemoteProcess(IntPtr process)
        {
            if (ps4 == null) { return; }
            Disconnect();
        }

        public bool ReadRemoteMemory(IntPtr process, IntPtr address, ref byte[] buffer, int offset, int size)
        {
            if (ps4 == null) { return false; }
            ulong uaddress = (ulong)(address.ToInt64()+offset);

            lock (sync)
            {
                if (uaddress >= KernelBase)
                    buffer = ps4.KernelReadMemory(uaddress, size);
                else
                    buffer = ps4.ReadMemory(process.ToInt32(), uaddress, size);
                return buffer.Length != 0;
            }
        }

        public bool WriteRemoteMemory(IntPtr process, IntPtr address, ref byte[] buffer, int offset, int size)
        {
            if (ps4 == null) { return false; }
            ulong uaddress = (ulong)(address.ToInt64() + offset);

            lock (sync)
            {
                try
                {
                    if (uaddress >= KernelBase)
                    {
                        return false;
//                        throw new NotImplementedException();
//                        ps4.KernelWriteMemory(uaddress, buffer);
                    }
                    else
                        ps4.WriteMemory(process.ToInt32(), uaddress, buffer);                 
                }
                catch (Exception ex)
                {
                    host.Logger.Log(ex);
                    return false;
                }
            }

            return true;
        }

        public void ControlRemoteProcess(IntPtr process, ControlRemoteProcessAction action)
        {
            if (ps4 == null) { return; }
            if (!ps4.IsDebugging) { return; }
            
            switch (action)
            {
                case ControlRemoteProcessAction.Suspend:
                    ps4.ProcessStop();
                    break;

                case ControlRemoteProcessAction.Resume:
                    ps4.ProcessResume();
                    break;

                case ControlRemoteProcessAction.Terminate:
                    ps4.ProcessKill();
                    break;
            }
        }

        public bool AttachDebuggerToProcess(IntPtr id)
        {
            if (ps4 == null) { return false; }
            if (ps4.IsDebugging) { return false; }

            lock (sync)
            {
                ps4.AttachDebugger(id.ToInt32(), new DebuggerInterruptCallback(this.DebuggerInterruptCallback));
                ps4.ProcessResume();
            }

            return true;
        }

        public void DetachDebuggerFromProcess(IntPtr id)
        {
            if (ps4 == null) { return; }
//            if (ps4.IsDebugging) { return; }

            lock (sync)
            {
                ps4.DetachDebugger();
            }
        }

        private void DebuggerInterruptCallback(uint lwpid, uint status, string tdname, regs regs, fpregs fpregs, dbregs dbregs)
        {
            ExceptionCode = status;
            Registers = regs;
            DebugRegisters = dbregs;

            areDebugEvent.Set();
        }

        public bool AwaitDebugEvent(ref DebugEvent evt, int timeoutInMilliseconds)
        {
            bool isSignaled = areDebugEvent.WaitOne(timeoutInMilliseconds);
            if (isSignaled)
            {
                if ((DebugRegisters.dr6 & 1) == 1)
                    evt.ExceptionInfo.CausedBy = HardwareBreakpointRegister.Dr0;
                else if ((DebugRegisters.dr6 & 2) == 2)
                    evt.ExceptionInfo.CausedBy = HardwareBreakpointRegister.Dr1;
                else if ((DebugRegisters.dr6 & 4) == 4)
                    evt.ExceptionInfo.CausedBy = HardwareBreakpointRegister.Dr2;
                else if ((DebugRegisters.dr6 & 8) == 8)
                    evt.ExceptionInfo.CausedBy = HardwareBreakpointRegister.Dr3;
                else
                    evt.ExceptionInfo.CausedBy = HardwareBreakpointRegister.InvalidRegister;

                evt.ExceptionInfo.ExceptionCode = (IntPtr)ExceptionCode;
//                evt.ExceptionInfo.ExceptionFlags = (IntPtr)0x0000000000000000;
                evt.ExceptionInfo.ExceptionAddress = (IntPtr)Registers.r_rip;

                evt.ExceptionInfo.Registers.Rax = (IntPtr)Registers.r_rax;
                evt.ExceptionInfo.Registers.Rbx = (IntPtr)Registers.r_rbx;
                evt.ExceptionInfo.Registers.Rcx = (IntPtr)Registers.r_rcx;
                evt.ExceptionInfo.Registers.Rdx = (IntPtr)Registers.r_rdx;
                evt.ExceptionInfo.Registers.Rdi = (IntPtr)Registers.r_rdi;
                evt.ExceptionInfo.Registers.Rsi = (IntPtr)Registers.r_rsi;
                evt.ExceptionInfo.Registers.Rsp = (IntPtr)Registers.r_rsp;
                evt.ExceptionInfo.Registers.Rbp = (IntPtr)Registers.r_rbp;
                evt.ExceptionInfo.Registers.Rip = (IntPtr)Registers.r_rip;
                evt.ExceptionInfo.Registers.R8 = (IntPtr)Registers.r_r8;
                evt.ExceptionInfo.Registers.R9 = (IntPtr)Registers.r_r9;
                evt.ExceptionInfo.Registers.R10 = (IntPtr)Registers.r_r10;
                evt.ExceptionInfo.Registers.R11 = (IntPtr)Registers.r_r11;
                evt.ExceptionInfo.Registers.R12 = (IntPtr)Registers.r_r12;
                evt.ExceptionInfo.Registers.R13 = (IntPtr)Registers.r_r13;
                evt.ExceptionInfo.Registers.R14 = (IntPtr)Registers.r_r14;
                evt.ExceptionInfo.Registers.R15 = (IntPtr)Registers.r_r15;
            }

            return isSignaled;
        }

        public void HandleDebugEvent(ref DebugEvent evt)
        {
            if (ps4 == null) { return; }
            if (!ps4.IsDebugging) { return; }

            lock (sync)
            {
                ps4.ProcessResume();
            }
        }

        public bool SetHardwareBreakpoint(IntPtr id, IntPtr address, HardwareBreakpointRegister register, HardwareBreakpointTrigger trigger, HardwareBreakpointSize size, bool set)
        {
            if (ps4 == null) { return false; }
            if (!ps4.IsDebugging) { return false; }

            int index = 0;
            switch (register)
            {
                case HardwareBreakpointRegister.InvalidRegister:
                    return false;
                case HardwareBreakpointRegister.Dr0:
                    index = 0;
                    break;

                case HardwareBreakpointRegister.Dr1:
                    index = 1;
                    break;

                case HardwareBreakpointRegister.Dr2:
                    index = 2;
                    break;

                case HardwareBreakpointRegister.Dr3:
                    index = 3;
                    break;
            }

            WATCHPT_LENGTH len = WATCHPT_LENGTH.DBREG_DR7_LEN_1;
            switch (size)
            {
                case HardwareBreakpointSize.Size1:
                    len = WATCHPT_LENGTH.DBREG_DR7_LEN_1;
                    break;

                case HardwareBreakpointSize.Size2:
                    len = WATCHPT_LENGTH.DBREG_DR7_LEN_2;
                    break;

                case HardwareBreakpointSize.Size4:
                    len = WATCHPT_LENGTH.DBREG_DR7_LEN_4;
                    break;

                case HardwareBreakpointSize.Size8:
                    len = WATCHPT_LENGTH.DBREG_DR7_LEN_8;
                    break;
            }

            WATCHPT_BREAKTYPE type = WATCHPT_BREAKTYPE.DBREG_DR7_EXEC;
            switch (trigger)
            {
                case HardwareBreakpointTrigger.Execute:
                    type = WATCHPT_BREAKTYPE.DBREG_DR7_EXEC;
                    break;

                case HardwareBreakpointTrigger.Access:
                    type = WATCHPT_BREAKTYPE.DBREG_DR7_RDWR;
                    break;

                case HardwareBreakpointTrigger.Write:
                    type = WATCHPT_BREAKTYPE.DBREG_DR7_WRONLY;
                    break;
            }

            lock (sync)
            {
                ps4.ChangeWatchpoint(index, set, len, type, (ulong)address.ToInt64());
            }

            return true;
        }
        
    public int ConnectServer(string ip, short port)
    {
         return -1;
    }

    public bool OpenDumpFile(IntPtr dumpFilePath)
    {
         return false;
    }        
    }
}
