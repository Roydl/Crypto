#if NET5_0_OR_GREATER && RELEASE
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

        private static readonly TestCaseData[] BenchmarkTestData =
        {
            new(ChecksumAlgo.Adler32, 65536),
            new(ChecksumAlgo.Crc16, 65536),
            new(ChecksumAlgo.Crc32, 65536),
            new(ChecksumAlgo.Crc32Xz, 65536),
            new(ChecksumAlgo.Crc32Posix, 65536),
            new(ChecksumAlgo.Crc64, 65536),
            new(ChecksumAlgo.Crc64Xz, 65536),
            new(ChecksumAlgo.Sha256, 65536)
        };

        private static readonly ConcurrentDictionary<string, ConcurrentBag<double>> BenchmarkResults = new(Environment.ProcessorCount, BenchmarkTestData.Length);

        [OneTimeTearDown]
        [SetCulture("en-US")]
        public void CreateResultFiles()
        {
            if (!BenchmarkResults.Any())
                return;
            var dir = TestContext.CurrentContext.TestDirectory;
            Parallel.ForEach(BenchmarkResults, pair =>
            {
                var (key, value) = pair;
                var file = Path.Combine(dir, $"__Benchmark-{string.Concat(key.Split(Path.GetInvalidFileNameChars()))}.txt");
                var sorted = value.OrderByDescending(x => x).ToArray();
                var digits = BenchmarkRepeats.ToString(NumberFormatInfo.InvariantInfo).Length;
                var content =
                    $"Average: {sorted.Sum() / sorted.Length:0.0,6} MiB/s" +
                    Environment.NewLine +
                    $"   Best: {sorted[0]:0.0,6} MiB/s" +
                    Environment.NewLine +
                    $"  Worst: {sorted[^1]:0.0,6} MiB/s" +
                    Environment.NewLine +
                    Environment.NewLine +
                    $"Results of {sorted.Length} runs with a total duration of {sorted.Length * 9} seconds:" +
                    Environment.NewLine +
                    string.Join(Environment.NewLine, sorted.Select((x, i) => $"{(i + 1).ToString().PadLeft(digits)}: {x:0.0,6} MiB/s"));
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
                rate = Math.Max(total / sw.Elapsed.TotalSeconds / 1024 / 1024, rate);
            }

            if (!saveResults)
            {
                TestContext.Write(@"  {0} Benchmark - Throughput: '{1:0.0} MiB/s'; ", algorithm.AlgorithmName, rate);
                switch (packetSize)
                {
                    case > 1024:
                        TestContext.Write(@"Packet Size: '{0:0} KiB';", packetSize / 1024);
                        break;
                    default:
                        TestContext.Write(@"Packet Size: '{0:0} Bytes';", packetSize);
                        break;
                }
                return;
            }

            var key = $"{algorithm.AlgorithmName}@{packetSize}";
            if (!BenchmarkResults.ContainsKey(key))
                BenchmarkResults[key] = new ConcurrentBag<double>();
            BenchmarkResults[key].Add(rate);
        }

        [Test]
        [TestCaseSource(nameof(BenchmarkTestData))]
        public void BenchmarkOnce(ChecksumAlgo algorithm, int dataSize) =>
            RunBenchmark(algorithm.GetDefaultInstance(), dataSize, false);

        [Explicit]
        [Test]
        [TestCaseSource(nameof(BenchmarkTestData))]
        [Repeat(BenchmarkRepeats)]
        public void BenchmarkRepeat(ChecksumAlgo algorithm, int dataSize) =>
            RunBenchmark(algorithm.GetDefaultInstance(), dataSize, true);
    }
}
#endif
