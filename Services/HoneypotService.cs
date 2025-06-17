using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace FirewallApp.Services
{
    public class HoneypotService
    {
        private readonly string _cowrieConfigPath;
        private readonly string _tpotConfigPath;
        private Process _cowrieProcess;
        private Process _tpotProcess;
        private readonly ConcurrentQueue<HoneypotEvent> _events;
        private bool _isRunning;
        private TcpListener _tcpListener;

        public HoneypotService()
        {
            _cowrieConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Config", "cowrie.cfg");
            _tpotConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Config", "tpot.yml");
            _events = new ConcurrentQueue<HoneypotEvent>();
        }

        public async Task StartHoneypot()
        {
            if (_isRunning) return;

            try
            {
                // Cowrie başlatma
                _cowrieProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "cowrie",
                        Arguments = $"-c {_cowrieConfigPath}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                _cowrieProcess.OutputDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        ParseCowrieEvent(e.Data);
                    }
                };

                _cowrieProcess.Start();
                _cowrieProcess.BeginOutputReadLine();

                // T-Pot başlatma
                _tpotProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "docker-compose",
                        Arguments = $"-f {_tpotConfigPath} up -d",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                _tpotProcess.Start();
                await _tpotProcess.WaitForExitAsync();

                // TCP Listener başlatma
                _tcpListener = new TcpListener(IPAddress.Any, 2222); // SSH portu
                _tcpListener.Start();
                _ = AcceptConnectionsAsync();

                _isRunning = true;
            }
            catch (Exception ex)
            {
                throw new Exception("Honeypot başlatılamadı: " + ex.Message);
            }
        }

        private async Task AcceptConnectionsAsync()
        {
            while (_isRunning)
            {
                try
                {
                    var client = await _tcpListener.AcceptTcpClientAsync();
                    _ = HandleConnectionAsync(client);
                }
                catch (Exception ex)
                {
                    LogError($"Bağlantı kabul hatası: {ex.Message}");
                }
            }
        }

        private async Task HandleConnectionAsync(TcpClient client)
        {
            try
            {
                var remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
                var event_ = new HoneypotEvent
                {
                    Timestamp = DateTime.Now,
                    SourceIP = remoteEndPoint?.Address.ToString(),
                    SourcePort = remoteEndPoint?.Port ?? 0,
                    EventType = "Connection",
                    Details = "Yeni bağlantı tespit edildi"
                };

                _events.Enqueue(event_);

                // Bağlantıyı Cowrie'ye yönlendir
                using var stream = client.GetStream();
                // Cowrie ile iletişim kur
            }
            catch (Exception ex)
            {
                LogError($"Bağlantı işleme hatası: {ex.Message}");
            }
            finally
            {
                client.Close();
            }
        }

        private void ParseCowrieEvent(string eventData)
        {
            var event_ = new HoneypotEvent
            {
                Timestamp = DateTime.Now,
                Source = "Cowrie",
                RawData = eventData,
                // Diğer event özelliklerini parse et
            };

            _events.Enqueue(event_);
        }

        public void StopHoneypot()
        {
            if (!_isRunning) return;

            try
            {
                _cowrieProcess?.Kill();
                _tpotProcess?.Kill();
                _tcpListener?.Stop();
                _isRunning = false;
            }
            catch (Exception ex)
            {
                throw new Exception("Honeypot durdurulamadı: " + ex.Message);
            }
        }

        private void LogError(string message)
        {
            var event_ = new HoneypotEvent
            {
                Timestamp = DateTime.Now,
                EventType = "Error",
                Details = message
            };

            _events.Enqueue(event_);
        }

        public HoneypotEvent[] GetEvents()
        {
            return _events.ToArray();
        }
    }

    public class HoneypotEvent
    {
        public DateTime Timestamp { get; set; }
        public string Source { get; set; }
        public string RawData { get; set; }
        public string EventType { get; set; }
        public string SourceIP { get; set; }
        public int SourcePort { get; set; }
        public string Details { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Command { get; set; }
    }
} 