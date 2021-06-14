#if NET5_0_OR_GREATER
namespace Roydl.Crypto.Test.BenchmarkTests
{
    using System;
    using NUnit.Framework;

    [TestFixture]
    [NonParallelizable]
    [Platform(Include = TestVars.PlatformCross)]
    public class ChecksumTests
    {
        private static readonly TestCaseData[] BigTestData =
        {
            new(ChecksumAlgo.Adler32, 65535),
            new(ChecksumAlgo.Crc8, 65535),
            new(ChecksumAlgo.Crc16, 65535),
            new(ChecksumAlgo.Crc32, 65535),
            new(ChecksumAlgo.Crc64Xz, 65535),
            new(ChecksumAlgo.Crc82, 65535),
            new(ChecksumAlgo.Md5, 65535),
            new(ChecksumAlgo.Sha1, 65535),
            new(ChecksumAlgo.Sha256, 65535),
            new(ChecksumAlgo.Sha384, 65535),
            new(ChecksumAlgo.Sha512, 65535)
        };

        private static readonly TestCaseData[] SmallTestData =
        {
            new(ChecksumAlgo.Crc16, 60),
            new(ChecksumAlgo.Crc32, 60),
            new(ChecksumAlgo.Crc64Xz, 60),
        };

        [Test]
        [TestCaseSource(nameof(BigTestData))]
        [TestCaseSource(nameof(SmallTestData))]
        [Category("Performance")]
        public void Benchmark_DataThroughput(ChecksumAlgo algorithm, int dataSize)
        {
            var inst = algorithm.GetDefaultInstance();
            var data = new byte[dataSize];
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
                    inst.ComputeHash(data);
                    total += data.Length;
                }
                sw.Stop();
                rate = Math.Max(total / sw.Elapsed.TotalSeconds / 1024 / 1024, rate);
            }

            TestContext.Write(@"  Benchmark Throughput [Algorithm: {0}; ", algorithm);
            switch (dataSize)
            {
                case > 1024:
                    TestContext.Write(@"Data Size: {0:0.} KiB", dataSize / 1024);
                    break;
                default:
                    TestContext.Write(@"Data Size: {0:0.} B", dataSize);
                    break;
            }
            TestContext.Write(@"]: {0:0.0} MiB/s", rate);
        }
    }
}
#endif
