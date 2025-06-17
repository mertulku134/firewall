using System;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace FirewallApp.Services
{
    public class FileIntegrityService
    {
        private readonly ConcurrentDictionary<string, string> _fileHashes;
        private readonly string _baseDirectory;
        private readonly List<string> _monitoredExtensions;
        private readonly FileSystemWatcher _watcher;
        private bool _isMonitoring;

        public event EventHandler<FileIntegrityEvent> FileChanged;

        public FileIntegrityService(string baseDirectory, List<string> monitoredExtensions = null)
        {
            _baseDirectory = baseDirectory;
            _monitoredExtensions = monitoredExtensions ?? new List<string> { ".exe", ".dll", ".sys", ".bat", ".ps1" };
            _fileHashes = new ConcurrentDictionary<string, string>();
            _watcher = new FileSystemWatcher(baseDirectory)
            {
                IncludeSubdirectories = true,
                EnableRaisingEvents = false
            };

            _watcher.Changed += OnFileChanged;
            _watcher.Created += OnFileCreated;
            _watcher.Deleted += OnFileDeleted;
            _watcher.Renamed += OnFileRenamed;
        }

        public async Task StartMonitoringAsync()
        {
            if (_isMonitoring) return;

            try
            {
                // Mevcut dosyaların hash'lerini hesapla
                await CalculateInitialHashesAsync();
                
                _watcher.EnableRaisingEvents = true;
                _isMonitoring = true;
            }
            catch (Exception ex)
            {
                throw new Exception($"Dosya izleme başlatılamadı: {ex.Message}");
            }
        }

        public void StopMonitoring()
        {
            if (!_isMonitoring) return;

            _watcher.EnableRaisingEvents = false;
            _isMonitoring = false;
        }

        private async Task CalculateInitialHashesAsync()
        {
            var files = Directory.GetFiles(_baseDirectory, "*.*", SearchOption.AllDirectories);
            
            foreach (var file in files)
            {
                if (ShouldMonitorFile(file))
                {
                    var hash = await CalculateFileHashAsync(file);
                    _fileHashes[file] = hash;
                }
            }
        }

        private bool ShouldMonitorFile(string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLower();
            return _monitoredExtensions.Contains(extension);
        }

        private async Task<string> CalculateFileHashAsync(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = await Task.Run(() => sha256.ComputeHash(stream));
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
            catch (Exception ex)
            {
                throw new Exception($"Hash hesaplanamadı: {ex.Message}");
            }
        }

        private async void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            if (!ShouldMonitorFile(e.FullPath)) return;

            try
            {
                var newHash = await CalculateFileHashAsync(e.FullPath);
                var oldHash = _fileHashes.GetValueOrDefault(e.FullPath);

                if (oldHash != null && oldHash != newHash)
                {
                    _fileHashes[e.FullPath] = newHash;
                    FileChanged?.Invoke(this, new FileIntegrityEvent
                    {
                        FilePath = e.FullPath,
                        EventType = "Changed",
                        OldHash = oldHash,
                        NewHash = newHash,
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch (Exception ex)
            {
                // Log error
            }
        }

        private async void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (!ShouldMonitorFile(e.FullPath)) return;

            try
            {
                var hash = await CalculateFileHashAsync(e.FullPath);
                _fileHashes[e.FullPath] = hash;

                FileChanged?.Invoke(this, new FileIntegrityEvent
                {
                    FilePath = e.FullPath,
                    EventType = "Created",
                    NewHash = hash,
                    Timestamp = DateTime.Now
                });
            }
            catch (Exception ex)
            {
                // Log error
            }
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            if (!ShouldMonitorFile(e.FullPath)) return;

            if (_fileHashes.TryRemove(e.FullPath, out var oldHash))
            {
                FileChanged?.Invoke(this, new FileIntegrityEvent
                {
                    FilePath = e.FullPath,
                    EventType = "Deleted",
                    OldHash = oldHash,
                    Timestamp = DateTime.Now
                });
            }
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (!ShouldMonitorFile(e.FullPath)) return;

            if (_fileHashes.TryRemove(e.OldFullPath, out var hash))
            {
                _fileHashes[e.FullPath] = hash;

                FileChanged?.Invoke(this, new FileIntegrityEvent
                {
                    FilePath = e.FullPath,
                    OldFilePath = e.OldFullPath,
                    EventType = "Renamed",
                    OldHash = hash,
                    NewHash = hash,
                    Timestamp = DateTime.Now
                });
            }
        }

        public Dictionary<string, string> GetCurrentHashes()
        {
            return new Dictionary<string, string>(_fileHashes);
        }
    }

    public class FileIntegrityEvent
    {
        public string FilePath { get; set; }
        public string OldFilePath { get; set; }
        public string EventType { get; set; }
        public string OldHash { get; set; }
        public string NewHash { get; set; }
        public DateTime Timestamp { get; set; }
    }
} 