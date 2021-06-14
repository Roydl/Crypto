//#define PERF

namespace Roydl.Crypto.Test.ChecksumTests
{
    using System;
    using System.Numerics;
    using Checksum;
    using NUnit.Framework;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = TestVars.PlatformCross)]
    public class CrcTests
    {
        public enum CrcType
        {
            Crc,
            Crc10,
            Crc11,
            Crc12,
            Crc13,
            Crc14,
            Crc15,
            Crc16,
            Crc17,
            Crc21,
            Crc24,
            Crc30,
            Crc31,
            Crc32,
            Crc40,
            Crc64,
            Crc82
        }

        private static readonly TestCaseData[] PresetTestData =
        {
            #region CRC-8 to CRC-15

            new(CrcType.Crc, CrcOptions.Crc.Default, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.Autosar, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.Bluetooth, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.Cdma2000, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.Darc, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.DvbS2, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.GsmA, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.GsmB, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.I4321, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.ICode, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.Lte, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.Maxim, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.MifareMad, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.Nrsc5, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.OpenSafety, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.Rohc, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.SaeJ1850, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.Tech3250, TestVarsType.InitOnly, null),
            new(CrcType.Crc, CrcOptions.Crc.Wcdma, TestVarsType.InitOnly, null),

            new(CrcType.Crc10, CrcOptions.Crc10.Default, TestVarsType.InitOnly, null),
            new(CrcType.Crc10, CrcOptions.Crc10.Cdma2000, TestVarsType.InitOnly, null),
            new(CrcType.Crc10, CrcOptions.Crc10.Gsm, TestVarsType.InitOnly, null),

            new(CrcType.Crc11, CrcOptions.Crc11.Default, TestVarsType.InitOnly, null),
            new(CrcType.Crc11, CrcOptions.Crc11.Umts, TestVarsType.InitOnly, null),

            new(CrcType.Crc12, CrcOptions.Crc12.Default, TestVarsType.InitOnly, null),
            new(CrcType.Crc12, CrcOptions.Crc12.Dect, TestVarsType.InitOnly, null),
            new(CrcType.Crc12, CrcOptions.Crc12.Gsm, TestVarsType.InitOnly, null),
            new(CrcType.Crc12, CrcOptions.Crc12.Umts, TestVarsType.InitOnly, null),

            new(CrcType.Crc13, CrcOptions.Crc13.Default, TestVarsType.InitOnly, null),

            new(CrcType.Crc14, CrcOptions.Crc14.Default, TestVarsType.InitOnly, null),
            new(CrcType.Crc14, CrcOptions.Crc14.Gsm, TestVarsType.InitOnly, null),

            new(CrcType.Crc15, CrcOptions.Crc15.Default, TestVarsType.InitOnly, null),
            new(CrcType.Crc15, CrcOptions.Crc15.Mpt1327, TestVarsType.InitOnly, null),

            #endregion

            #region CRC-16

            new(CrcType.Crc16, CrcOptions.Crc16.Default, TestVarsType.TestString, "3825"),
            new(CrcType.Crc16, CrcOptions.Crc16.Default, TestVarsType.RangeString, "30f1"),

            new(CrcType.Crc16, CrcOptions.Crc16.A, TestVarsType.TestString, "2205"),
            new(CrcType.Crc16, CrcOptions.Crc16.A, TestVarsType.RangeString, "d4c4"),

            new(CrcType.Crc16, CrcOptions.Crc16.Buypass, TestVarsType.TestString, "3ce2"),
            new(CrcType.Crc16, CrcOptions.Crc16.Buypass, TestVarsType.RangeString, "7197"),

            new(CrcType.Crc16, CrcOptions.Crc16.Cdma2000, TestVarsType.TestString, "134b"),
            new(CrcType.Crc16, CrcOptions.Crc16.Cdma2000, TestVarsType.RangeString, "023b"),

            new(CrcType.Crc16, CrcOptions.Crc16.Cms, TestVarsType.TestString, "3cc6"),
            new(CrcType.Crc16, CrcOptions.Crc16.Cms, TestVarsType.RangeString, "2bad"),

            new(CrcType.Crc16, CrcOptions.Crc16.Dds110, TestVarsType.TestString, "3c3a"),
            new(CrcType.Crc16, CrcOptions.Crc16.Dds110, TestVarsType.RangeString, "2d0e"),

            new(CrcType.Crc16, CrcOptions.Crc16.DectR, TestVarsType.TestString, "db7a"),
            new(CrcType.Crc16, CrcOptions.Crc16.DectR, TestVarsType.RangeString, "c7ab"),

            new(CrcType.Crc16, CrcOptions.Crc16.DectX, TestVarsType.TestString, "db7b"),
            new(CrcType.Crc16, CrcOptions.Crc16.DectX, TestVarsType.RangeString, "c7aa"),

            new(CrcType.Crc16, CrcOptions.Crc16.Dnp, TestVarsType.TestString, "b742"),
            new(CrcType.Crc16, CrcOptions.Crc16.Dnp, TestVarsType.RangeString, "8892"),

            new(CrcType.Crc16, CrcOptions.Crc16.En13757, TestVarsType.TestString, "f58d"),
            new(CrcType.Crc16, CrcOptions.Crc16.En13757, TestVarsType.RangeString, "7bae"),

            new(CrcType.Crc16, CrcOptions.Crc16.Genibus, TestVarsType.TestString, "d777"),
            new(CrcType.Crc16, CrcOptions.Crc16.Genibus, TestVarsType.RangeString, "ceb2"),

            new(CrcType.Crc16, CrcOptions.Crc16.Gsm, TestVarsType.TestString, "53b7"),
            new(CrcType.Crc16, CrcOptions.Crc16.Gsm, TestVarsType.RangeString, "0247"),

            new(CrcType.Crc16, CrcOptions.Crc16.Ibm3740, TestVarsType.TestString, "2888"),
            new(CrcType.Crc16, CrcOptions.Crc16.Ibm3740, TestVarsType.RangeString, "314d"),

            new(CrcType.Crc16, CrcOptions.Crc16.IbmSdlc, TestVarsType.TestString, "88db"),
            new(CrcType.Crc16, CrcOptions.Crc16.IbmSdlc, TestVarsType.RangeString, "e715"),

            new(CrcType.Crc16, CrcOptions.Crc16.Kermit, TestVarsType.TestString, "7405"),
            new(CrcType.Crc16, CrcOptions.Crc16.Kermit, TestVarsType.RangeString, "b7d9"),

            new(CrcType.Crc16, CrcOptions.Crc16.Lj1200, TestVarsType.TestString, "ab65"),
            new(CrcType.Crc16, CrcOptions.Crc16.Lj1200, TestVarsType.RangeString, "2af6"),

            new(CrcType.Crc16, CrcOptions.Crc16.Maxim, TestVarsType.TestString, "c7da"),
            new(CrcType.Crc16, CrcOptions.Crc16.Maxim, TestVarsType.RangeString, "cf0e"),

            new(CrcType.Crc16, CrcOptions.Crc16.Mcrf4Xx, TestVarsType.TestString, "7724"),
            new(CrcType.Crc16, CrcOptions.Crc16.Mcrf4Xx, TestVarsType.RangeString, "18ea"),

            new(CrcType.Crc16, CrcOptions.Crc16.ModBus, TestVarsType.TestString, "1c25"),
            new(CrcType.Crc16, CrcOptions.Crc16.ModBus, TestVarsType.RangeString, "6cab"),

            new(CrcType.Crc16, CrcOptions.Crc16.Riello, TestVarsType.TestString, "5363"),
            new(CrcType.Crc16, CrcOptions.Crc16.Riello, TestVarsType.RangeString, "bc78"),

            new(CrcType.Crc16, CrcOptions.Crc16.SpiFujitsu, TestVarsType.TestString, "a258"),
            new(CrcType.Crc16, CrcOptions.Crc16.SpiFujitsu, TestVarsType.RangeString, "113b"),

            new(CrcType.Crc16, CrcOptions.Crc16.T10Dif, TestVarsType.TestString, "17a1"),
            new(CrcType.Crc16, CrcOptions.Crc16.T10Dif, TestVarsType.RangeString, "d71a"),

            new(CrcType.Crc16, CrcOptions.Crc16.TeleDisk, TestVarsType.TestString, "f6ca"),
            new(CrcType.Crc16, CrcOptions.Crc16.TeleDisk, TestVarsType.RangeString, "48da"),

            new(CrcType.Crc16, CrcOptions.Crc16.Tms37157, TestVarsType.TestString, "8cda"),
            new(CrcType.Crc16, CrcOptions.Crc16.Tms37157, TestVarsType.RangeString, "e3ed"),

            new(CrcType.Crc16, CrcOptions.Crc16.Usb, TestVarsType.TestString, "e3da"),
            new(CrcType.Crc16, CrcOptions.Crc16.Usb, TestVarsType.RangeString, "9354"),

            new(CrcType.Crc16, CrcOptions.Crc16.XModem, TestVarsType.TestString, "ac48"),
            new(CrcType.Crc16, CrcOptions.Crc16.XModem, TestVarsType.RangeString, "fdb8"),

            #endregion

            #region CRC-17 and CRC-21

            new(CrcType.Crc17, CrcOptions.Crc17.Default, TestVarsType.TestString, "2c38d"),
            new(CrcType.Crc17, CrcOptions.Crc17.Default, TestVarsType.RangeString, "182d1"),

            new(CrcType.Crc21, CrcOptions.Crc21.Default, TestVarsType.TestString, "128a0d"),
            new(CrcType.Crc21, CrcOptions.Crc21.Default, TestVarsType.RangeString, "16c0c0"),

            #endregion

            #region CRC-24

            new(CrcType.Crc24, CrcOptions.Crc24.Default, TestVarsType.TestString, "20777c"),
            new(CrcType.Crc24, CrcOptions.Crc24.Default, TestVarsType.RangeString, "38c4f4"),

            new(CrcType.Crc24, CrcOptions.Crc24.Ble, TestVarsType.TestString, "ffa950"),
            new(CrcType.Crc24, CrcOptions.Crc24.Ble, TestVarsType.RangeString, "acab7d"),

            new(CrcType.Crc24, CrcOptions.Crc24.FlexRayA, TestVarsType.TestString, "2c70f2"),
            new(CrcType.Crc24, CrcOptions.Crc24.FlexRayA, TestVarsType.RangeString, "294438"),

            new(CrcType.Crc24, CrcOptions.Crc24.FlexRayB, TestVarsType.TestString, "0e3a1d"),
            new(CrcType.Crc24, CrcOptions.Crc24.FlexRayB, TestVarsType.RangeString, "d5ee31"),

            new(CrcType.Crc24, CrcOptions.Crc24.Interlaken, TestVarsType.TestString, "5d5302"),
            new(CrcType.Crc24, CrcOptions.Crc24.Interlaken, TestVarsType.RangeString, "39d91d"),

            new(CrcType.Crc24, CrcOptions.Crc24.LteA, TestVarsType.TestString, "d62e8f"),
            new(CrcType.Crc24, CrcOptions.Crc24.LteA, TestVarsType.RangeString, "b1f403"),

            new(CrcType.Crc24, CrcOptions.Crc24.LteB, TestVarsType.TestString, "137ceb"),
            new(CrcType.Crc24, CrcOptions.Crc24.LteB, TestVarsType.RangeString, "da2736"),

            new(CrcType.Crc24, CrcOptions.Crc24.Os9, TestVarsType.TestString, "634135"),
            new(CrcType.Crc24, CrcOptions.Crc24.Os9, TestVarsType.RangeString, "b6660c"),

            #endregion

            #region CRC-30 and CRC-31

            new(CrcType.Crc30, CrcOptions.Crc30.Default, TestVarsType.TestString, "36037067"),
            new(CrcType.Crc30, CrcOptions.Crc30.Default, TestVarsType.RangeString, "18b1ef87"),

            new(CrcType.Crc31, CrcOptions.Crc31.Default, TestVarsType.TestString, "1a76718d"),
            new(CrcType.Crc31, CrcOptions.Crc31.Default, TestVarsType.RangeString, "37e0c69c"),

            #endregion

            #region CRC-32

            new(CrcType.Crc32, CrcOptions.Crc32.Default, TestVarsType.TestString, "784dd132"),
            new(CrcType.Crc32, CrcOptions.Crc32.Default, TestVarsType.RangeString, "7ad6d652"),

            new(CrcType.Crc32, CrcOptions.Crc32.Autosar, TestVarsType.TestString, "d8132eb0"),
            new(CrcType.Crc32, CrcOptions.Crc32.Autosar, TestVarsType.RangeString, "a628d0d8"),

            new(CrcType.Crc32, CrcOptions.Crc32.CdRomEdc, TestVarsType.TestString, "2d8195d8"),
            new(CrcType.Crc32, CrcOptions.Crc32.CdRomEdc, TestVarsType.RangeString, "901cf0dd"),

            new(CrcType.Crc32, CrcOptions.Crc32.Q, TestVarsType.TestString, "1fc717d7"),
            new(CrcType.Crc32, CrcOptions.Crc32.Q, TestVarsType.RangeString, "95d827df"),

            new(CrcType.Crc32, CrcOptions.Crc32.BZip2, TestVarsType.TestString, "d962895d"),
            new(CrcType.Crc32, CrcOptions.Crc32.BZip2, TestVarsType.RangeString, "45cbc18b"),

            new(CrcType.Crc32, CrcOptions.Crc32.C, TestVarsType.TestString, "5185664b"),
            new(CrcType.Crc32, CrcOptions.Crc32.C, TestVarsType.RangeString, "09cd6072"),

            new(CrcType.Crc32, CrcOptions.Crc32.D, TestVarsType.TestString, "d1ebff71"),
            new(CrcType.Crc32, CrcOptions.Crc32.D, TestVarsType.RangeString, "ab5be79c"),

            new(CrcType.Crc32, CrcOptions.Crc32.JamCrc, TestVarsType.TestString, "87b22ecd"),
            new(CrcType.Crc32, CrcOptions.Crc32.JamCrc, TestVarsType.RangeString, "852929ad"),

            new(CrcType.Crc32, CrcOptions.Crc32.Mpeg2, TestVarsType.TestString, "269d76a2"),
            new(CrcType.Crc32, CrcOptions.Crc32.Mpeg2, TestVarsType.RangeString, "ba343e74"),

            new(CrcType.Crc32, CrcOptions.Crc32.Posix, TestVarsType.TestString, "1e665426"),
            new(CrcType.Crc32, CrcOptions.Crc32.Posix, TestVarsType.RangeString, "d17dacbe"),

            new(CrcType.Crc32, CrcOptions.Crc32.Xfer, TestVarsType.TestString, "b006037d"),
            new(CrcType.Crc32, CrcOptions.Crc32.Xfer, TestVarsType.RangeString, "7964bec3"),

            #endregion

            #region CRC-40

            new(CrcType.Crc40, CrcOptions.Crc40.Default, TestVarsType.TestString, "10df47b471"),
            new(CrcType.Crc40, CrcOptions.Crc40.Default, TestVarsType.RangeString, "f46d283fad"),

            #endregion

            #region CRC-64

            new(CrcType.Crc64, CrcOptions.Crc64.Default, TestVarsType.TestString, "02f6563f4a3751ff"),
            new(CrcType.Crc64, CrcOptions.Crc64.Default, TestVarsType.RangeString, "59d3e35dccce4de9"),

            new(CrcType.Crc64, CrcOptions.Crc64.We, TestVarsType.TestString, "d00f8e47e656f4d0"),
            new(CrcType.Crc64, CrcOptions.Crc64.We, TestVarsType.RangeString, "eafb40d259d5882c"),

            new(CrcType.Crc64, CrcOptions.Crc64.Xz, TestVarsType.TestString, "6275e834da84732f"),
            new(CrcType.Crc64, CrcOptions.Crc64.Xz, TestVarsType.RangeString, "2472ea52fe9d7cf0"),

            new(CrcType.Crc64, CrcOptions.Crc64.GoIso, TestVarsType.TestString, "287c72fe50000000"),
            new(CrcType.Crc64, CrcOptions.Crc64.GoIso, TestVarsType.RangeString, "e6d3b62e3b9bd7f1"),

            #endregion

            #region CRC-82

            new(CrcType.Crc82, CrcOptions.Crc82.Default, TestVarsType.TestString, "16348ec7ea7f602abd024"),
            new(CrcType.Crc82, CrcOptions.Crc82.Default, TestVarsType.RangeString, "3dff868d831e5a22b515a"),

            #endregion
        };

        private static dynamic CreateInstance(CrcType crcType, Enum algorithm) =>
            crcType switch
            {
                CrcType.Crc => new Crc<byte>((CrcOptions.Crc)algorithm),
                CrcType.Crc10 => new Crc<ushort>((CrcOptions.Crc10)algorithm),
                CrcType.Crc11 => new Crc<ushort>((CrcOptions.Crc11)algorithm),
                CrcType.Crc12 => new Crc<ushort>((CrcOptions.Crc12)algorithm),
                CrcType.Crc13 => new Crc<ushort>((CrcOptions.Crc13)algorithm),
                CrcType.Crc14 => new Crc<ushort>((CrcOptions.Crc14)algorithm),
                CrcType.Crc15 => new Crc<ushort>((CrcOptions.Crc15)algorithm),
                CrcType.Crc16 => new Crc<ushort>((CrcOptions.Crc16)algorithm),
                CrcType.Crc17 => new Crc<uint>((CrcOptions.Crc17)algorithm),
                CrcType.Crc21 => new Crc<uint>((CrcOptions.Crc21)algorithm),
                CrcType.Crc24 => new Crc<uint>((CrcOptions.Crc24)algorithm),
                CrcType.Crc30 => new Crc<uint>((CrcOptions.Crc30)algorithm),
                CrcType.Crc31 => new Crc<uint>((CrcOptions.Crc31)algorithm),
                CrcType.Crc32 => new Crc<uint>((CrcOptions.Crc32)algorithm),
                CrcType.Crc40 => new Crc<ulong>((CrcOptions.Crc40)algorithm),
                CrcType.Crc64 => new Crc<ulong>((CrcOptions.Crc64)algorithm),
                CrcType.Crc82 => new Crc<BigInteger>((CrcOptions.Crc82)algorithm),
                _ => throw new ArgumentOutOfRangeException(nameof(crcType), crcType, null)
            };

        [Test]
        [TestCaseSource(nameof(PresetTestData))]
        [Category("Method")]
        public void Instance_ComputeHash(CrcType crcType, Enum algorithm, TestVarsType varsType, string expectedHash)
        {
            var instance = CreateInstance(crcType, algorithm);
            Assert.AreEqual(88, CrcConfigManager.CacheCapacityLimit);
            Assert.AreEqual((int)Math.Ceiling(CrcConfigManager.CacheCapacityLimit / 3d), CrcConfigManager.CacheCapacity);
            Assert.AreEqual(Environment.ProcessorCount, CrcConfigManager.CacheConcurrencyLevel);
            Assert.LessOrEqual(CrcConfigManager.CacheSize, CrcConfigManager.CacheCapacity);
            Assert.GreaterOrEqual(CrcConfigManager.CacheSize, 1);
            TestContext.WriteLine(@"Cached: {0:00}/{1:00}", CrcConfigManager.CacheSize, CrcConfigManager.CacheCapacity);
            switch (varsType)
            {
                case TestVarsType.InitOnly:
                    return;
                case TestVarsType.TestString:
                    instance.ComputeHash(TestVars.TestStr);
                    break;
                case TestVarsType.RangeString:
                    instance.ComputeHash(TestVars.RangeStr);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedHash, instance.Hash);
            Assert.AreEqual(expectedHash, (string)instance);
        }

#if NET5_0_OR_GREATER && RELEASE && PERF
        private static readonly TestCaseData[] PerfTestData =
        {
            new(CrcType.Crc, CrcOptions.Crc.Default),
            new(CrcType.Crc16, CrcOptions.Crc16.Default),
            new(CrcType.Crc16, CrcOptions.Crc16.Buypass),
            new(CrcType.Crc32, CrcOptions.Crc32.Default),
            new(CrcType.Crc32, CrcOptions.Crc32.Xfer),
            new(CrcType.Crc64, CrcOptions.Crc64.Default),
            new(CrcType.Crc64, CrcOptions.Crc64.GoIso),
            new(CrcType.Crc82, CrcOptions.Crc82.Default)
        };

        [Test]
        [Explicit]
        [NonParallelizable]
        [TestCaseSource(nameof(PerfTestData))]
        public void Throughput(CrcType crcType, Enum algorithm)
        {
            const int cycles = 3;

            var instance = (IChecksumAlgorithm)CreateInstance(crcType, algorithm);

            var data = new byte[ushort.MaxValue];
            TestVars.Randomizer.NextBytes(data);

            var sw = TestVars.StopWatch;
            var rate = 0d;

            for (var i = 0; i < cycles; i++)
            {
                var total = 0L;
                sw.Restart();
                while (sw.Elapsed < TimeSpan.FromSeconds(cycles))
                {
                    instance.ComputeHash(data);
                    total += data.Length;
                }
                sw.Stop();
                rate = Math.Max(total / sw.Elapsed.TotalSeconds / 1024 / 1024, rate);
            }

            TestContext.WriteLine(@"Throughput: {0:0.0} MiB/s", rate);
        }
#endif
    }
}
