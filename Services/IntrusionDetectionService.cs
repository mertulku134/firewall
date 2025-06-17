using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Concurrent;

namespace FirewallApp.Services
{
    public class IntrusionDetectionService
    {
        private readonly string _snortConfigPath;
        private readonly string _suricataConfigPath;
        private Process _snortProcess;
        private Process _suricataProcess;
        private readonly ConcurrentQueue<Alert> _alerts;
        private bool _isRunning;

        public IntrusionDetectionService()
        {
            _snortConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Config", "snort.conf");
            _suricataConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Config", "suricata.yaml");
            _alerts = new ConcurrentQueue<Alert>();
        }

        public async Task StartIDS()
        {
            if (_isRunning) return;

            try
            {
                // Snort başlatma
                _snortProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "snort",
                        Arguments = $"-c {_snortConfigPath} -A console -q",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                _snortProcess.OutputDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        ParseSnortAlert(e.Data);
                    }
                };

                _snortProcess.Start();
                _snortProcess.BeginOutputReadLine();

                // Suricata başlatma
                _suricataProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "suricata",
                        Arguments = $"-c {_suricataConfigPath} -i eth0",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                _suricataProcess.OutputDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        ParseSuricataAlert(e.Data);
                    }
                };

                _suricataProcess.Start();
                _suricataProcess.BeginOutputReadLine();

                _isRunning = true;
            }
            catch (Exception ex)
            {
                throw new Exception("IDS başlatılamadı: " + ex.Message);
            }
        }

        private void ParseSnortAlert(string alertData)
        {
            // Snort alert formatını parse et
            var alert = new Alert
            {
                Timestamp = DateTime.Now,
                Source = "Snort",
                RawData = alertData,
                // Diğer alert özelliklerini parse et
            };

            _alerts.Enqueue(alert);
        }

        private void ParseSuricataAlert(string alertData)
        {
            // Suricata alert formatını parse et
            var alert = new Alert
            {
                Timestamp = DateTime.Now,
                Source = "Suricata",
                RawData = alertData,
                // Diğer alert özelliklerini parse et
            };

            _alerts.Enqueue(alert);
        }

        public void StopIDS()
        {
            if (!_isRunning) return;

            try
            {
                _snortProcess?.Kill();
                _suricataProcess?.Kill();
                _isRunning = false;
            }
            catch (Exception ex)
            {
                throw new Exception("IDS durdurulamadı: " + ex.Message);
            }
        }

        public Alert[] GetAlerts()
        {
            return _alerts.ToArray();
        }
    }

    public class Alert
    {
        public DateTime Timestamp { get; set; }
        public string Source { get; set; }
        public string RawData { get; set; }
        public string AttackType { get; set; }
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string Protocol { get; set; }
        public string Severity { get; set; }
    }
} 