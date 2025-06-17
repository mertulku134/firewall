using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Security.Principal;

namespace FirewallApp
{
    public class FirewallService
    {
        public bool IsFirewallEnabled()
        {
            try
            {
                Process process = new Process();
                process.StartInfo.FileName = "netsh";
                process.StartInfo.Arguments = "advfirewall show allprofiles state";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                return output.Contains("ON");
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool BlockApplication(string applicationPath)
        {
            try
            {
                Process process = new Process();
                process.StartInfo.FileName = "netsh";
                process.StartInfo.Arguments = $"advfirewall firewall add rule name=\"Block {applicationPath}\" dir=out action=block program=\"{applicationPath}\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                process.WaitForExit();

                return process.ExitCode == 0;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool AllowApplication(string applicationPath)
        {
            try
            {
                Process process = new Process();
                process.StartInfo.FileName = "netsh";
                process.StartInfo.Arguments = $"advfirewall firewall add rule name=\"Allow {applicationPath}\" dir=out action=allow program=\"{applicationPath}\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                process.WaitForExit();

                return process.ExitCode == 0;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool IsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
} 