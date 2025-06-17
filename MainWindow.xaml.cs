using System;
using System.Windows;
using System.Windows.Controls;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using FirewallApp.Services;

namespace FirewallApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly IntrusionDetectionService _idsService;
        private readonly HoneypotService _honeypotService;
        private readonly LoggingService _loggingService;
        private readonly ObservableCollection<Alert> _idsAlerts;
        private readonly ObservableCollection<HoneypotEvent> _honeypotEvents;
        private readonly ObservableCollection<SecurityEvent> _securityEvents;

        public MainWindow()
        {
            InitializeComponent();
            
            _idsService = new IntrusionDetectionService();
            _honeypotService = new HoneypotService();
            _loggingService = new LoggingService();

            _idsAlerts = new ObservableCollection<Alert>();
            _honeypotEvents = new ObservableCollection<HoneypotEvent>();
            _securityEvents = new ObservableCollection<SecurityEvent>();

            InitializeDataGrids();
            StartServices();
        }

        private void InitializeDataGrids()
        {
            // IDS/IPS DataGrid
            var idsGrid = FindName("IdsAlertsGrid") as DataGrid;
            if (idsGrid != null)
            {
                idsGrid.ItemsSource = _idsAlerts;
            }

            // Honeypot DataGrid
            var honeypotGrid = FindName("HoneypotEventsGrid") as DataGrid;
            if (honeypotGrid != null)
            {
                honeypotGrid.ItemsSource = _honeypotEvents;
            }

            // Logs DataGrid
            var logsGrid = FindName("SecurityEventsGrid") as DataGrid;
            if (logsGrid != null)
            {
                logsGrid.ItemsSource = _securityEvents;
            }
        }

        private async void StartServices()
        {
            try
            {
                await _idsService.StartIDS();
                await _honeypotService.StartHoneypot();

                // IDS/IPS olaylarını dinle
                Task.Run(async () =>
                {
                    while (true)
                    {
                        var alerts = _idsService.GetAlerts();
                        foreach (var alert in alerts)
                        {
                            Application.Current.Dispatcher.Invoke(() =>
                            {
                                _idsAlerts.Add(alert);
                                _loggingService.LogEvent(new SecurityEvent
                                {
                                    Timestamp = alert.Timestamp,
                                    EventType = "IDS Alert",
                                    SourceIP = alert.SourceIP,
                                    DestinationIP = alert.DestinationIP,
                                    SourcePort = alert.SourcePort,
                                    DestinationPort = alert.DestinationPort,
                                    Protocol = alert.Protocol,
                                    AttackType = alert.AttackType,
                                    Details = alert.RawData,
                                    Severity = alert.Severity
                                });
                            });
                        }
                        await Task.Delay(1000);
                    }
                });

                // Honeypot olaylarını dinle
                Task.Run(async () =>
                {
                    while (true)
                    {
                        var events = _honeypotService.GetEvents();
                        foreach (var event_ in events)
                        {
                            Application.Current.Dispatcher.Invoke(() =>
                            {
                                _honeypotEvents.Add(event_);
                                _loggingService.LogEvent(new SecurityEvent
                                {
                                    Timestamp = event_.Timestamp,
                                    EventType = "Honeypot Event",
                                    SourceIP = event_.SourceIP,
                                    SourcePort = event_.SourcePort,
                                    Details = event_.Details
                                });
                            });
                        }
                        await Task.Delay(1000);
                    }
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Servisler başlatılırken hata oluştu: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void GenerateReport_Click(object sender, RoutedEventArgs e)
        {
            var startDatePicker = FindName("StartDatePicker") as DatePicker;
            var endDatePicker = FindName("EndDatePicker") as DatePicker;

            if (startDatePicker?.SelectedDate == null || endDatePicker?.SelectedDate == null)
            {
                MessageBox.Show("Lütfen başlangıç ve bitiş tarihlerini seçin.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                await _loggingService.GenerateReport(startDatePicker.SelectedDate.Value, endDatePicker.SelectedDate.Value);
                MessageBox.Show("Rapor başarıyla oluşturuldu.", "Bilgi", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Rapor oluşturulurken hata oluştu: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            _idsService.StopIDS();
            _honeypotService.StopHoneypot();
        }
    }
}