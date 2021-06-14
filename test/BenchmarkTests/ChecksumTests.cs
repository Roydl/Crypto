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
        private static readonly TestCaseData[] PerfTestData =
        {
            new(ChecksumAlgo.Adler32, 65535),
            new(ChecksumAlgo.Crc8, 65535),
            new(ChecksumAlgo.Crc16, 60),
            new(ChecksumAlgo.Crc16, 65535),
            new(ChecksumAlgo.Crc32, 60),
            new(ChecksumAlgo.Crc32, 65535),
            new(ChecksumAlgo.Crc64Xz, 60),
            new(ChecksumAlgo.Crc64Xz, 65535),
            new(ChecksumAlgo.Crc82, 65535),
            new(ChecksumAlgo.Md5, 65535),
            new(ChecksumAlgo.Sha1, 65535),
            new(ChecksumAlgo.Sha256, 65535),
            new(ChecksumAlgo.Sha384, 65535),
            new(ChecksumAlgo.Sha512, 65535)
        };

        [Test]
        [TestCaseSource(nameof(PerfTestData))]
        [Category("Performance")]
        public void DataThroughput(ChecksumAlgo algorithm, int dataSize)
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
            TestContext.WriteLine(@"Throughput: {0:0.0} MiB/s", rate);
        }
    }
}
#endif
