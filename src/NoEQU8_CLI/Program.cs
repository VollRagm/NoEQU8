using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NoEQU8_CLI
{
    class Program
    {
        static void Main(string[] args)
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                var isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
                if (!isElevated) Log.Fatal("Please run this as administrator.");
            }

            int processId = 0;

            if(args.Length > 0)
            {
                if (!int.TryParse(args[0], out processId))
                    Log.Fatal("Please provide a valid process id!");
            }
            else
            {
                var pidString = Log.QueryString("Please enter the Process ID the process you want to whitelist: ");

                if (!int.TryParse(pidString, out processId))
                    Log.Fatal("Please provide a valid process id!");
            }

            if (Process.GetProcessById(processId) == null)
                Log.Fatal($"Process with ID {processId} not found!");

            WritePid(processId);
            MapDriver();
            Log.Info("Done.");
            Console.ReadLine();
        }

        static void WritePid(int pid)
        {
            //ghetto solution, dont blame me for it
            File.WriteAllText("C:\\pid.txt", pid.ToString());
        }

        static void MapDriver()
        {
            var currentDirectory = Directory.GetCurrentDirectory();
            ProcessStartInfo psi = new ProcessStartInfo()
            {
                FileName = Path.Combine(currentDirectory, "physmeme.exe"),
                Arguments = "NoEQU8.sys",
                UseShellExecute = false
            };

            Process.Start(psi);
            Thread.Sleep(3000);
        }
    }
}
