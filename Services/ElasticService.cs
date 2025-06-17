using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;
using System.Collections.Generic;

namespace FirewallApp.Services
{
    public class ElasticService
    {
        private readonly HttpClient _httpClient;
        private readonly string _elasticUrl;
        private readonly string _indexName;

        public ElasticService(string elasticUrl = "http://localhost:9200", string indexName = "firewall-logs")
        {
            _httpClient = new HttpClient();
            _elasticUrl = elasticUrl;
            _indexName = indexName;
        }

        public async Task SendLogAsync(SecurityEvent securityEvent)
        {
            try
            {
                var json = JsonSerializer.Serialize(securityEvent);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                
                var response = await _httpClient.PostAsync($"{_elasticUrl}/{_indexName}/_doc", content);
                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                throw new Exception($"ELK log gönderimi başarısız: {ex.Message}");
            }
        }

        public async Task<List<SecurityEvent>> SearchLogsAsync(string query, DateTime startDate, DateTime endDate)
        {
            try
            {
                var searchQuery = new
                {
                    query = new
                    {
                        bool = new
                        {
                            must = new[]
                            {
                                new { match = new { query = query } },
                                new { range = new { Timestamp = new { gte = startDate, lte = endDate } } }
                            }
                        }
                    }
                };

                var json = JsonSerializer.Serialize(searchQuery);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync($"{_elasticUrl}/{_indexName}/_search", content);
                response.EnsureSuccessStatusCode();

                var result = await response.Content.ReadAsStringAsync();
                // Elasticsearch yanıtını parse et ve SecurityEvent listesine dönüştür
                return ParseElasticResponse(result);
            }
            catch (Exception ex)
            {
                throw new Exception($"ELK arama başarısız: {ex.Message}");
            }
        }

        private List<SecurityEvent> ParseElasticResponse(string response)
        {
            // Elasticsearch yanıtını parse et
            var result = new List<SecurityEvent>();
            // TODO: Implement parsing logic
            return result;
        }
    }
} 