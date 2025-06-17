using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;
using System.Collections.Generic;

namespace FirewallApp.Services
{
    public class NotificationService
    {
        private readonly HttpClient _httpClient;
        private readonly string _slackWebhookUrl;
        private readonly string _teamsWebhookUrl;
        private readonly string _emailApiKey;
        private readonly string _emailFrom;

        public NotificationService(
            string slackWebhookUrl = null,
            string teamsWebhookUrl = null,
            string emailApiKey = null,
            string emailFrom = null)
        {
            _httpClient = new HttpClient();
            _slackWebhookUrl = slackWebhookUrl;
            _teamsWebhookUrl = teamsWebhookUrl;
            _emailApiKey = emailApiKey;
            _emailFrom = emailFrom;
        }

        public async Task SendAlertAsync(SecurityAlert alert)
        {
            var tasks = new List<Task>();

            if (!string.IsNullOrEmpty(_slackWebhookUrl))
            {
                tasks.Add(SendSlackNotificationAsync(alert));
            }

            if (!string.IsNullOrEmpty(_teamsWebhookUrl))
            {
                tasks.Add(SendTeamsNotificationAsync(alert));
            }

            if (!string.IsNullOrEmpty(_emailApiKey))
            {
                tasks.Add(SendEmailNotificationAsync(alert));
            }

            await Task.WhenAll(tasks);
        }

        private async Task SendSlackNotificationAsync(SecurityAlert alert)
        {
            try
            {
                var message = new
                {
                    text = $"*Güvenlik Uyarısı*\n" +
                          $"*Tür:* {alert.Type}\n" +
                          $"*Kaynak IP:* {alert.SourceIP}\n" +
                          $"*Hedef IP:* {alert.DestinationIP}\n" +
                          $"*Port:* {alert.Port}\n" +
                          $"*Protokol:* {alert.Protocol}\n" +
                          $"*Detaylar:* {alert.Details}\n" +
                          $"*Zaman:* {alert.Timestamp}"
                };

                var json = JsonSerializer.Serialize(message);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync(_slackWebhookUrl, content);
                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                throw new Exception($"Slack bildirimi gönderilemedi: {ex.Message}");
            }
        }

        private async Task SendTeamsNotificationAsync(SecurityAlert alert)
        {
            try
            {
                var message = new
                {
                    title = "Güvenlik Uyarısı",
                    text = $"**Tür:** {alert.Type}\n" +
                          $"**Kaynak IP:** {alert.SourceIP}\n" +
                          $"**Hedef IP:** {alert.DestinationIP}\n" +
                          $"**Port:** {alert.Port}\n" +
                          $"**Protokol:** {alert.Protocol}\n" +
                          $"**Detaylar:** {alert.Details}\n" +
                          $"**Zaman:** {alert.Timestamp}",
                    themeColor = "FF0000"
                };

                var json = JsonSerializer.Serialize(message);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync(_teamsWebhookUrl, content);
                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                throw new Exception($"Teams bildirimi gönderilemedi: {ex.Message}");
            }
        }

        private async Task SendEmailNotificationAsync(SecurityAlert alert)
        {
            try
            {
                var message = new
                {
                    from = _emailFrom,
                    to = alert.Recipients,
                    subject = $"Güvenlik Uyarısı: {alert.Type}",
                    text = $"Güvenlik Uyarısı\n\n" +
                          $"Tür: {alert.Type}\n" +
                          $"Kaynak IP: {alert.SourceIP}\n" +
                          $"Hedef IP: {alert.DestinationIP}\n" +
                          $"Port: {alert.Port}\n" +
                          $"Protokol: {alert.Protocol}\n" +
                          $"Detaylar: {alert.Details}\n" +
                          $"Zaman: {alert.Timestamp}"
                };

                var json = JsonSerializer.Serialize(message);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                _httpClient.DefaultRequestHeaders.Add("X-API-Key", _emailApiKey);
                var response = await _httpClient.PostAsync("https://api.email-service.com/send", content);
                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                throw new Exception($"E-posta bildirimi gönderilemedi: {ex.Message}");
            }
        }
    }

    public class SecurityAlert
    {
        public string Type { get; set; }
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }
        public List<string> Recipients { get; set; }
    }
} 