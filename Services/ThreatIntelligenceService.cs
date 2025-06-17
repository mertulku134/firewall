using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using System.Collections.Generic;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Responses;

namespace FirewallApp.Services
{
    public class ThreatIntelligenceService
    {
        private readonly HttpClient _httpClient;
        private readonly DatabaseReader _geoIpReader;
        private readonly string _abuseIpDbApiKey;
        private readonly string _virustotalApiKey;

        public ThreatIntelligenceService(
            string geoIpDbPath = "GeoLite2-City.mmdb",
            string abuseIpDbApiKey = null,
            string virustotalApiKey = null)
        {
            _httpClient = new HttpClient();
            _geoIpReader = new DatabaseReader(geoIpDbPath);
            _abuseIpDbApiKey = abuseIpDbApiKey;
            _virustotalApiKey = virustotalApiKey;
        }

        public async Task<GeoLocationInfo> GetGeoLocationAsync(string ipAddress)
        {
            try
            {
                var response = await Task.Run(() => _geoIpReader.City(ipAddress));
                return new GeoLocationInfo
                {
                    Country = response.Country.Name,
                    City = response.City.Name,
                    Latitude = response.Location.Latitude,
                    Longitude = response.Location.Longitude,
                    TimeZone = response.Location.TimeZone
                };
            }
            catch (Exception ex)
            {
                throw new Exception($"GeoIP sorgusu başarısız: {ex.Message}");
            }
        }

        public async Task<ThreatInfo> CheckThreatIntelligenceAsync(string ipAddress)
        {
            var threatInfo = new ThreatInfo { IpAddress = ipAddress };

            // AbuseIPDB kontrolü
            if (!string.IsNullOrEmpty(_abuseIpDbApiKey))
            {
                var abuseInfo = await CheckAbuseIPDBAsync(ipAddress);
                threatInfo.AbuseScore = abuseInfo.Score;
                threatInfo.AbuseReports = abuseInfo.Reports;
            }

            // VirusTotal kontrolü
            if (!string.IsNullOrEmpty(_virustotalApiKey))
            {
                var vtInfo = await CheckVirusTotalAsync(ipAddress);
                threatInfo.VirusTotalScore = vtInfo.Score;
                threatInfo.VirusTotalDetections = vtInfo.Detections;
            }

            return threatInfo;
        }

        private async Task<AbuseIPDBInfo> CheckAbuseIPDBAsync(string ipAddress)
        {
            try
            {
                _httpClient.DefaultRequestHeaders.Add("Key", _abuseIpDbApiKey);
                var response = await _httpClient.GetAsync($"https://api.abuseipdb.com/api/v2/check?ipAddress={ipAddress}");
                response.EnsureSuccessStatusCode();

                var content = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<AbuseIPDBResponse>(content);

                return new AbuseIPDBInfo
                {
                    Score = result.Data.AbuseConfidenceScore,
                    Reports = result.Data.TotalReports
                };
            }
            catch (Exception ex)
            {
                throw new Exception($"AbuseIPDB sorgusu başarısız: {ex.Message}");
            }
        }

        private async Task<VirusTotalInfo> CheckVirusTotalAsync(string ipAddress)
        {
            try
            {
                _httpClient.DefaultRequestHeaders.Add("x-apikey", _virustotalApiKey);
                var response = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/ip_addresses/{ipAddress}");
                response.EnsureSuccessStatusCode();

                var content = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<VirusTotalResponse>(content);

                return new VirusTotalInfo
                {
                    Score = result.Data.Attributes.LastAnalysisStats.Malicious,
                    Detections = result.Data.Attributes.LastAnalysisResults
                };
            }
            catch (Exception ex)
            {
                throw new Exception($"VirusTotal sorgusu başarısız: {ex.Message}");
            }
        }
    }

    public class GeoLocationInfo
    {
        public string Country { get; set; }
        public string City { get; set; }
        public double? Latitude { get; set; }
        public double? Longitude { get; set; }
        public string TimeZone { get; set; }
    }

    public class ThreatInfo
    {
        public string IpAddress { get; set; }
        public int? AbuseScore { get; set; }
        public int? AbuseReports { get; set; }
        public int? VirusTotalScore { get; set; }
        public Dictionary<string, object> VirusTotalDetections { get; set; }
    }

    public class AbuseIPDBInfo
    {
        public int Score { get; set; }
        public int Reports { get; set; }
    }

    public class VirusTotalInfo
    {
        public int Score { get; set; }
        public Dictionary<string, object> Detections { get; set; }
    }

    // API Response sınıfları
    public class AbuseIPDBResponse
    {
        public AbuseIPDBData Data { get; set; }
    }

    public class AbuseIPDBData
    {
        public int AbuseConfidenceScore { get; set; }
        public int TotalReports { get; set; }
    }

    public class VirusTotalResponse
    {
        public VirusTotalData Data { get; set; }
    }

    public class VirusTotalData
    {
        public VirusTotalAttributes Attributes { get; set; }
    }

    public class VirusTotalAttributes
    {
        public LastAnalysisStats LastAnalysisStats { get; set; }
        public Dictionary<string, object> LastAnalysisResults { get; set; }
    }

    public class LastAnalysisStats
    {
        public int Malicious { get; set; }
    }
} 