using System;
using System.IO;
using System.Text.Json;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Linq;

namespace FirewallApp.Services
{
    public class LoggingService
    {
        private readonly string _logDirectory;
        private readonly string _reportDirectory;
        private readonly ConcurrentQueue<SecurityEvent> _events;
        private readonly object _lockObject = new object();

        public LoggingService()
        {
            _logDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
            _reportDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Reports");
            _events = new ConcurrentQueue<SecurityEvent>();

            Directory.CreateDirectory(_logDirectory);
            Directory.CreateDirectory(_reportDirectory);
        }

        public void LogEvent(SecurityEvent securityEvent)
        {
            _events.Enqueue(securityEvent);
            SaveEventToFile(securityEvent);
        }

        private void SaveEventToFile(SecurityEvent securityEvent)
        {
            var logFile = Path.Combine(_logDirectory, $"security_{DateTime.Now:yyyyMMdd}.log");
            var logEntry = JsonSerializer.Serialize(securityEvent);

            lock (_lockObject)
            {
                File.AppendAllText(logFile, logEntry + Environment.NewLine);
            }
        }

        public async Task GenerateReport(DateTime startDate, DateTime endDate)
        {
            var report = new SecurityReport
            {
                StartDate = startDate,
                EndDate = endDate,
                Events = _events.Where(e => e.Timestamp >= startDate && e.Timestamp <= endDate).ToArray(),
                Summary = new ReportSummary
                {
                    TotalEvents = _events.Count,
                    AttackTypes = _events.GroupBy(e => e.AttackType)
                        .ToDictionary(g => g.Key, g => g.Count()),
                    TopSourceIPs = _events.GroupBy(e => e.SourceIP)
                        .OrderByDescending(g => g.Count())
                        .Take(10)
                        .ToDictionary(g => g.Key, g => g.Count()),
                    TopDestinationPorts = _events.GroupBy(e => e.DestinationPort)
                        .OrderByDescending(g => g.Count())
                        .Take(10)
                        .ToDictionary(g => g.Key.ToString(), g => g.Count())
                }
            };

            var reportFile = Path.Combine(_reportDirectory, $"report_{startDate:yyyyMMdd}_{endDate:yyyyMMdd}.json");
            var reportJson = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });

            await File.WriteAllTextAsync(reportFile, reportJson);
        }

        public SecurityEvent[] GetEvents(DateTime? startDate = null, DateTime? endDate = null)
        {
            return _events
                .Where(e => (!startDate.HasValue || e.Timestamp >= startDate.Value) &&
                           (!endDate.HasValue || e.Timestamp <= endDate.Value))
                .ToArray();
        }
    }

    public class SecurityEvent
    {
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; }
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string Protocol { get; set; }
        public string AttackType { get; set; }
        public string Details { get; set; }
        public string Severity { get; set; }
    }

    public class SecurityReport
    {
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public SecurityEvent[] Events { get; set; }
        public ReportSummary Summary { get; set; }
    }

    public class ReportSummary
    {
        public int TotalEvents { get; set; }
        public Dictionary<string, int> AttackTypes { get; set; }
        public Dictionary<string, int> TopSourceIPs { get; set; }
        public Dictionary<string, int> TopDestinationPorts { get; set; }
    }
} 