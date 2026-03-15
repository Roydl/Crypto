#if RELEASE
namespace Roydl.Crypto.Test.BenchmarkTests
{
    using System;
    using System.Collections.Concurrent;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Threading.Tasks;
    using Checksum;
    using NUnit.Framework;

    [TestFixture]
    [NonParallelizable]
    [Platform(Include = TestVars.PlatformCross)]
    [Category("Performance")]
    public class ChecksumPerformanceTests
    {
        private const int BenchmarkRepeats = 20;
        private const int DefaultDataSize = 65536;

        private static readonly TestCaseData[] BenchmarkTestData =
        [
            new(ChecksumAlgo.Adler32, DefaultDataSize),
            new(ChecksumAlgo.Crc16, DefaultDataSize),
            new(ChecksumAlgo.Crc32, DefaultDataSize),
            new(ChecksumAlgo.Crc32Xz, DefaultDataSize),
            new(ChecksumAlgo.Crc32Posix, DefaultDataSize),
            new(ChecksumAlgo.Crc64, DefaultDataSize),
            new(ChecksumAlgo.Crc64Xz, DefaultDataSize),
            new(ChecksumAlgo.Crc82, DefaultDataSize),
            new(ChecksumAlgo.Sha2, DefaultDataSize),
            new(ChecksumAlgo.Sha3, DefaultDataSize),
        ];

        private static readonly ConcurrentDictionary<string, ConcurrentBag<double>> BenchmarkResults =
            new(Environment.ProcessorCount, BenchmarkTestData.Length);

        [OneTimeTearDown]
        [SetCulture("en-US")]
        public void CreateResultFiles()
        {
            if (BenchmarkResults.IsEmpty)
                return;
            var dir = TestContext.CurrentContext.TestDirectory;
            Parallel.ForEach(BenchmarkResults, pair =>
            {
                var (key, value) = pair;
                var file = Path.Combine(dir, $"__Benchmark-{string.Concat(key.Split(Path.GetInvalidFileNameChars()))}.txt");
                var sorted = value.OrderByDescending(x => x).ToArray();
                var digits = BenchmarkRepeats.ToString(NumberFormatInfo.InvariantInfo).Length;
                var content =
                    $"Average: {sorted.Sum() / sorted.Length:0.000,6} GiB/s" +
                    Environment.NewLine +
                    $"   Best: {sorted[0]:0.000,6} GiB/s" +
                    Environment.NewLine +
                    $"  Worst: {sorted[^1]:0.000,6} GiB/s" +
                    Environment.NewLine +
                    Environment.NewLine +
                    $"Results of {sorted.Length} runs with a total duration of {sorted.Length * 9} seconds:" +
                    Environment.NewLine +
                    string.Join(Environment.NewLine, sorted.Select((x, i) => $"{(i + 1).ToString().PadLeft(digits)}: {x:0.000,6} GiB/s"));
                File.WriteAllText(file, content);
            });
        }

        private static void RunBenchmark(IChecksumAlgorithm algorithm, int packetSize, bool saveResults)
        {
            var data = new byte[packetSize];
            TestVars.Randomizer.NextBytes(data);

            const int cycles = 9 / 3;
            var sw = TestVars.StopWatch;
            var rate = 0d;
            for (var i = 0; i < cycles; i++)
            {
                var total = 0L;
                sw.Restart();
                while (sw.Elapsed < TimeSpan.FromSeconds(cycles))
                {
                    algorithm.ComputeHash(data);
                    total += data.Length;
                }
                sw.Stop();
                rate = Math.Max(total / sw.Elapsed.TotalSeconds / 1024 / 1024 / 1024, rate);
            }

            if (!saveResults)
            {
                TestContext.Write(@"{0} Benchmark - Throughput: '{1:0.000} GiB/s'; ", algorithm.AlgorithmName, rate);
                switch (packetSize)
                {
                    case > 1024:
                        TestContext.WriteLine(@"Packet Size: '{0:0} KiB';", packetSize / 1024);
                        break;
                    default:
                        TestContext.WriteLine(@"Packet Size: '{0:0} Bytes';", packetSize);
                        break;
                }
                return;
            }

            var key = $"{algorithm.AlgorithmName}@{packetSize}";
            if (!BenchmarkResults.ContainsKey(key))
                BenchmarkResults[key] = [];
            BenchmarkResults[key].Add(rate);
        }

        [Test]
        [TestCaseSource(nameof(BenchmarkTestData))]
        public void BenchmarkOnce(ChecksumAlgo algorithm, int packetSize) =>
            RunBenchmark(algorithm.GetDefaultInstance(), packetSize, false);

        [Explicit]
        [Test]
        [TestCaseSource(nameof(BenchmarkTestData))]
        [Repeat(BenchmarkRepeats)]
        public void BenchmarkRepeat(ChecksumAlgo algorithm, int packetSize) =>
            RunBenchmark(algorithm.GetDefaultInstance(), packetSize, true);
    }
}
#endif
