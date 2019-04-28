using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Collections;
using InfinityScript;

namespace setServerGametype
{
    public class setServerGametype : BaseScript
    {
        //[DllImport("kernel32.dll")]
        //private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr buffer, uint size, int lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, int lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll")]
        static extern int VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private static string modeText;

        public setServerGametype()
        {
            GSCFunctions.SetDvarIfUninitialized("sv_maxClientsMod", 0);
            GSCFunctions.SetDvarIfUninitialized("sv_gametypeName", "");
            StartAsync(setupGametype());
        }
        private static IEnumerator setupGametype()
        {
            yield return Wait(.5f);

            string mapname = GSCFunctions.GetDvar("mapname");
            string gametypeName = GSCFunctions.GetDvar("sv_gametypeName");
            if (gametypeName == "") yield break;
            if (gametypeName == "Exo") gametypeName = getExoGametype();

            //Utilities.PrintToConsole(gametypeName);

            string privateClients = GSCFunctions.GetDvar("sv_privateClients");
            string port = GSCFunctions.GetDvar("net_masterServerPort");
            modeText = @"gn\IW5\gt\" + gametypeName + @"\hc\0\pu\1\m\" + mapname + @"\px\-1\pn\\mr\\pc\" + privateClients + @"\ff\0\fg\\md\\kc\1\ac\1\d\2\qp\" + port + @"\vo\1\";

            //Utilities.PrintToConsole(modeText);

            yield return Wait(.5f);
            writeToServerInfoString(0x00200000, 0x10000000);
        }
        private static string getExoGametype()
        {
            string gametype = GSCFunctions.GetDvar("g_gametype");
            switch (gametype)
            {
                case "war":
                    return "Exo TDM";
                case "dm":
                    return "Exo FFA";
                case "infect":
                    return "Exo Infected";
                case "dom":
                    return "Exo Dom";
                case "sd":
                    return "Exo S&D";
                case "sab":
                    return "Exo Sabotage";
                case "koth":
                    return "Exo HQ";
                case "dd":
                    return "Exo Demo";
                case "ctf":
                    return "Exo CTF";
                case "gun":
                    return "Exo Gun Game";
                case "oic":
                    return "Exo Slammer";
                case "grnd":
                    return "Exo Dropzone";
                case "conf":
                    return "Exo KC";
                case "tdef":
                    return "Exo Team Def";
                default:
                    return "Exo Gamemode";
            }
        }

        public class scanning
        {
            public static bool canReadAndWriteMemory(IntPtr address, uint length)
            {
                MEMORY_BASIC_INFORMATION mem;
                VirtualQuery(address, out mem, length);

                if (/*mem.Protect == 0x40 || */mem.Protect == 0x04) return true;
                return false;
            }
            public static List<IntPtr> scanForServerInfo(int min, int max)
            {
                Process P = Process.GetCurrentProcess();
                List<IntPtr> ptrs = new List<IntPtr>();
                IntPtr currentAddr = new IntPtr(min);

                string s = null;
                byte[] buffer = new byte[1024];
                string test = @"gn\IW4\gt\fk";
                string key = "gn\\IW5\\gt\\";

                for (; (int)currentAddr < max; currentAddr += 1024)
                {
                    if (!canReadAndWriteMemory(currentAddr, 1024)) continue;

                    s = null;
                    ReadProcessMemory(P.Handle, currentAddr, buffer, 1024, 0);
                    s = Encoding.ASCII.GetString(buffer);//Mem.ReadString(currentAddr, 512);

                    if (!string.IsNullOrEmpty(s))
                    {
                        //Utilities.PrintToConsole("Address " + currentAddr.ToString("X"));
                        if (s.Contains(key))
                        {
                            int offset = s.IndexOf("gn");
                            //Utilities.PrintToConsole("Address Found " + (currentAddr + offset).ToString("X"));
                            //Find out if this is real or not
                            //printToConsole("Testing " + (currentAddr + offset).ToString("X"));
                            //uint oldProtect;
                            //VirtualProtect(currentAddr + offset, 512, 0x04, out oldProtect);
                            WriteString(currentAddr + offset, test, false);
                            //System.Threading.Thread.Sleep(50);
                            byte[] returnBuffer = new byte[test.Length];
                            ReadProcessMemory(P.Handle, currentAddr + offset, returnBuffer, 12, 0);
                            string returned = Encoding.ASCII.GetString(returnBuffer);
                            //VirtualProtect(currentAddr + offset, 512, oldProtect, out oldProtect);

                            if (test == returned)
                                ptrs.Add(currentAddr + offset);
                        }
                    }

                    //for (int i = 0; i < buffer.Length; i++)
                    //buffer[i] = 0;//Clear buffer from memory footprint

                }
                return ptrs;
            }

            public static string ReadString(IntPtr address, int maxlen = 0)
            {
                string ret = "";
                maxlen = (maxlen == 0) ? int.MaxValue : maxlen;

                byte[] buffer = new byte[maxlen];
                //uint oldProtect = 0x40;

                //if (protect)
                //VirtualProtect(new IntPtr(address), (uint)maxlen, 0x40, out oldProtect);

                ReadProcessMemory(Process.GetCurrentProcess().Handle, address, buffer, (uint)maxlen, 0);

                //if (protect)
                //VirtualProtect(new IntPtr(address), (uint)maxlen, oldProtect, out oldProtect);

                ret = Encoding.ASCII.GetString(buffer);

                return ret;
            }

            public static void WriteString(IntPtr address, string str, bool endZero = true)
            {
                byte[] strarr = Encoding.ASCII.GetBytes(str);

                Marshal.Copy(strarr, 0, address, strarr.Length);
                if (endZero) Marshal.WriteByte(address + str.Length, 0);
            }
        }
        public static void scanServerInfo(object sender, DoWorkEventArgs e)
        {
            int[] arguments = e.Argument as int[];
            e.Result = scanning.scanForServerInfo(arguments[0], arguments[1]);
        }
        private static void scanServerInfo_Completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Cancelled)
            {
                Utilities.PrintToConsole("Server gametype name search was cancelled for an unknown reason.");
                return;
            }
            if (e.Error != null)
            {
                Utilities.PrintToConsole("There was an error setting the server gametype name!: " + e.Error.Message);
                return;
            }

            List<IntPtr> addrs = e.Result as List<IntPtr>;
            if (addrs.Count == 0)
            {
                Utilities.PrintToConsole("There was an error setting the server gametype name: No addresses found!");
                return;
            }

            setServerInfoPtrs(addrs);
        }
        private static void setServerInfoPtrs(List<IntPtr> addrs)
        {
            if (addrs.Count > 0)
            {
                //save found address(es)
                string addrDvar = string.Join(" ", addrs);
                GSCFunctions.SetDvar("sv_serverinfo_addr", addrDvar);
                for (int i = 50; i <= addrs.Count * 50; i += 50)
                {
                    int index = (i / 50) - 1;
                    int addr = addrs[index].ToInt32();
                    //Log.Debug("Setting addr {0} with delay of {1}", addr.ToString("X"), i);
                    AfterDelay(i, () => setGametype(addr));
                }
                //foreach (IntPtr addr in addrs) AfterDelay(1000, () => setGametype((int)addr));
            }
            else
            {
                Utilities.PrintToConsole("Unable to set custom gametype name in server browser!");
                return;
            }
        }

        public static void writeToServerInfoString(int min, int max)
        {
            string sv_serverinfo_addr = GSCFunctions.GetDvar("sv_serverinfo_addr");
            if (string.IsNullOrEmpty(sv_serverinfo_addr) || sv_serverinfo_addr == "0") //first start
            {
                BackgroundWorker task = new BackgroundWorker();
                task.DoWork += scanServerInfo;
                task.RunWorkerAsync(new int[2] { min, max });

                task.RunWorkerCompleted += new RunWorkerCompletedEventHandler(scanServerInfo_Completed);
            }
            else
            {
                AfterDelay(1000, () =>
                {
                    //skip search, just load from sdvar
                    string[] parts = sv_serverinfo_addr.Split(' ');
                    int[] addrs = Array.ConvertAll(parts, int.Parse);
                    if (addrs.Length > 0)
                    {
                        for (int i = 50; i <= addrs.Length * 50; i += 50)
                        {
                            int index = (i / 50) - 1;
                            int addr = addrs[index];
                            //Log.Debug("Setting addr {0} with delay of {1}", addr.ToString("X"), i);
                            AfterDelay(i, () => setGametype(addr));
                        }
                    }
                });
            }
        }
        private static void setGametype(int ptr)
        {
            scanning.WriteString(new IntPtr(ptr), modeText);
        }
    }
}
