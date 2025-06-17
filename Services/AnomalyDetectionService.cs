using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.ML;
using Microsoft.ML.Data;

namespace FirewallApp.Services
{
    public class AnomalyDetectionService
    {
        private readonly MLContext _mlContext;
        private ITransformer _model;
        private readonly string _modelPath;
        private readonly List<NetworkTrafficData> _trainingData;

        public AnomalyDetectionService(string modelPath = "Models/anomaly_model.zip")
        {
            _mlContext = new MLContext();
            _modelPath = modelPath;
            _trainingData = new List<NetworkTrafficData>();
        }

        public void AddTrainingData(NetworkTrafficData data)
        {
            _trainingData.Add(data);
        }

        public async Task TrainModelAsync()
        {
            if (_trainingData.Count < 100)
            {
                throw new Exception("Eğitim için yeterli veri yok. En az 100 örnek gerekli.");
            }

            var trainingData = _mlContext.Data.LoadFromEnumerable(_trainingData);

            var pipeline = _mlContext.Transforms.Conversion.MapValueToKey("Label")
                .Append(_mlContext.Transforms.Concatenate("Features",
                    nameof(NetworkTrafficData.PacketSize),
                    nameof(NetworkTrafficData.PacketCount),
                    nameof(NetworkTrafficData.Protocol),
                    nameof(NetworkTrafficData.SourcePort),
                    nameof(NetworkTrafficData.DestinationPort)))
                .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
                .Append(_mlContext.AnomalyDetection.TrainIsolationForest(
                    numberOfSamples: 256,
                    contamination: 0.1,
                    numberOfTrees: 100));

            _model = pipeline.Fit(trainingData);
            await SaveModelAsync();
        }

        public async Task<bool> DetectAnomalyAsync(NetworkTrafficData data)
        {
            if (_model == null)
            {
                await LoadModelAsync();
            }

            var predictionEngine = _mlContext.Model.CreatePredictionEngine<NetworkTrafficData, AnomalyPrediction>(_model);
            var prediction = predictionEngine.Predict(data);

            return prediction.Score > 0.5; // Anomali eşiği
        }

        private async Task SaveModelAsync()
        {
            await Task.Run(() => _mlContext.Model.Save(_model, null, _modelPath));
        }

        private async Task LoadModelAsync()
        {
            if (!System.IO.File.Exists(_modelPath))
            {
                throw new Exception("Model dosyası bulunamadı.");
            }

            await Task.Run(() => _model = _mlContext.Model.Load(_modelPath, out var _));
        }
    }

    public class NetworkTrafficData
    {
        [LoadColumn(0)]
        public float PacketSize { get; set; }

        [LoadColumn(1)]
        public float PacketCount { get; set; }

        [LoadColumn(2)]
        public float Protocol { get; set; }

        [LoadColumn(3)]
        public float SourcePort { get; set; }

        [LoadColumn(4)]
        public float DestinationPort { get; set; }

        [LoadColumn(5)]
        public bool IsAnomaly { get; set; }
    }

    public class AnomalyPrediction
    {
        [VectorType]
        public float[] Score { get; set; }

        public float Prediction { get; set; }
    }
} 