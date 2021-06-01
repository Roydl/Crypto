namespace Roydl.Crypto.Test.ChecksumTests
{
    using System;
    using System.IO;
    using System.Numerics;
    using Checksum;
    using NUnit.Framework;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class CrcPresetTests
    {
        // Because we're using generic here, some hashes are padded.
        public sealed class CrcCustom<T> : ChecksumAlgorithm<CrcCustom<T>> where T : IFormattable
        {
            private CrcConfig<T> Current { get; }

            public CrcCustom(CrcConfig<T> config) : base(config.Bits) =>
                Current = config;

            public override void Encrypt(Stream stream)
            {
                if (stream == null)
                    throw new ArgumentNullException(nameof(stream));
                Current.ComputeHash(stream, out var num);
                if (num is BigInteger bi)
                {
                    HashNumber = (ulong)(bi & 0xffffffffffffffffuL);
                    var ba = bi.ToByteArray();
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(ba);
                    RawHash = ba;
                    return;
                }
                HashNumber = (ulong)(dynamic)num;
                RawHash = CryptoUtils.GetByteArray(HashNumber, RawHashSize);
            }
        }

        public enum CrcType
        {
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
            #region CRC-16

            new(CrcType.Crc16, Crc16Preset.Default, TestVarsType.TestString, "3825"),
            new(CrcType.Crc16, Crc16Preset.Default, TestVarsType.RangeString, "30f1"),

            new(CrcType.Crc16, Crc16Preset.A, TestVarsType.TestString, "2205"),
            new(CrcType.Crc16, Crc16Preset.A, TestVarsType.RangeString, "d4c4"),

            new(CrcType.Crc16, Crc16Preset.Buypass, TestVarsType.TestString, "3ce2"),
            new(CrcType.Crc16, Crc16Preset.Buypass, TestVarsType.RangeString, "7197"),

            new(CrcType.Crc16, Crc16Preset.Cdma2000, TestVarsType.TestString, "134b"),
            new(CrcType.Crc16, Crc16Preset.Cdma2000, TestVarsType.RangeString, "023b"),

            new(CrcType.Crc16, Crc16Preset.Cms, TestVarsType.TestString, "3cc6"),
            new(CrcType.Crc16, Crc16Preset.Cms, TestVarsType.RangeString, "2bad"),

            new(CrcType.Crc16, Crc16Preset.Dds110, TestVarsType.TestString, "3c3a"),
            new(CrcType.Crc16, Crc16Preset.Dds110, TestVarsType.RangeString, "2d0e"),

            new(CrcType.Crc16, Crc16Preset.DectR, TestVarsType.TestString, "db7a"),
            new(CrcType.Crc16, Crc16Preset.DectR, TestVarsType.RangeString, "c7ab"),

            new(CrcType.Crc16, Crc16Preset.DectX, TestVarsType.TestString, "db7b"),
            new(CrcType.Crc16, Crc16Preset.DectX, TestVarsType.RangeString, "c7aa"),

            new(CrcType.Crc16, Crc16Preset.Dnp, TestVarsType.TestString, "b742"),
            new(CrcType.Crc16, Crc16Preset.Dnp, TestVarsType.RangeString, "8892"),

            new(CrcType.Crc16, Crc16Preset.En13757, TestVarsType.TestString, "f58d"),
            new(CrcType.Crc16, Crc16Preset.En13757, TestVarsType.RangeString, "7bae"),

            new(CrcType.Crc16, Crc16Preset.Genibus, TestVarsType.TestString, "d777"),
            new(CrcType.Crc16, Crc16Preset.Genibus, TestVarsType.RangeString, "ceb2"),

            new(CrcType.Crc16, Crc16Preset.Gsm, TestVarsType.TestString, "53b7"),
            new(CrcType.Crc16, Crc16Preset.Gsm, TestVarsType.RangeString, "0247"),

            new(CrcType.Crc16, Crc16Preset.Ibm3740, TestVarsType.TestString, "2888"),
            new(CrcType.Crc16, Crc16Preset.Ibm3740, TestVarsType.RangeString, "314d"),

            new(CrcType.Crc16, Crc16Preset.IbmSdlc, TestVarsType.TestString, "88db"),
            new(CrcType.Crc16, Crc16Preset.IbmSdlc, TestVarsType.RangeString, "e715"),

            new(CrcType.Crc16, Crc16Preset.Kermit, TestVarsType.TestString, "7405"),
            new(CrcType.Crc16, Crc16Preset.Kermit, TestVarsType.RangeString, "b7d9"),

            new(CrcType.Crc16, Crc16Preset.Lj1200, TestVarsType.TestString, "ab65"),
            new(CrcType.Crc16, Crc16Preset.Lj1200, TestVarsType.RangeString, "2af6"),

            new(CrcType.Crc16, Crc16Preset.Maxim, TestVarsType.TestString, "c7da"),
            new(CrcType.Crc16, Crc16Preset.Maxim, TestVarsType.RangeString, "cf0e"),

            new(CrcType.Crc16, Crc16Preset.Mcrf4Xx, TestVarsType.TestString, "7724"),
            new(CrcType.Crc16, Crc16Preset.Mcrf4Xx, TestVarsType.RangeString, "18ea"),

            new(CrcType.Crc16, Crc16Preset.ModBus, TestVarsType.TestString, "1c25"),
            new(CrcType.Crc16, Crc16Preset.ModBus, TestVarsType.RangeString, "6cab"),

            new(CrcType.Crc16, Crc16Preset.Riello, TestVarsType.TestString, "5363"),
            new(CrcType.Crc16, Crc16Preset.Riello, TestVarsType.RangeString, "bc78"),

            new(CrcType.Crc16, Crc16Preset.SpiFujitsu, TestVarsType.TestString, "a258"),
            new(CrcType.Crc16, Crc16Preset.SpiFujitsu, TestVarsType.RangeString, "113b"),

            new(CrcType.Crc16, Crc16Preset.T10Dif, TestVarsType.TestString, "17a1"),
            new(CrcType.Crc16, Crc16Preset.T10Dif, TestVarsType.RangeString, "d71a"),

            new(CrcType.Crc16, Crc16Preset.TeleDisk, TestVarsType.TestString, "f6ca"),
            new(CrcType.Crc16, Crc16Preset.TeleDisk, TestVarsType.RangeString, "48da"),

            new(CrcType.Crc16, Crc16Preset.Tms37157, TestVarsType.TestString, "8cda"),
            new(CrcType.Crc16, Crc16Preset.Tms37157, TestVarsType.RangeString, "e3ed"),

            new(CrcType.Crc16, Crc16Preset.Usb, TestVarsType.TestString, "e3da"),
            new(CrcType.Crc16, Crc16Preset.Usb, TestVarsType.RangeString, "9354"),

            new(CrcType.Crc16, Crc16Preset.XModem, TestVarsType.TestString, "ac48"),
            new(CrcType.Crc16, Crc16Preset.XModem, TestVarsType.RangeString, "fdb8"),

            #endregion

            #region CRC-17 and CRC-21 (padded)

            new(CrcType.Crc17, Crc17Preset.Default, TestVarsType.TestString, "02c38d"),
            new(CrcType.Crc17, Crc17Preset.Default, TestVarsType.RangeString, "3182d1"),

            new(CrcType.Crc21, Crc21Preset.Default, TestVarsType.TestString, "128a0d"),
            new(CrcType.Crc21, Crc21Preset.Default, TestVarsType.RangeString, "16c0c0"),

            #endregion

            #region CRC-24

            new(CrcType.Crc24, Crc24Preset.Default, TestVarsType.TestString, "20777c"),
            new(CrcType.Crc24, Crc24Preset.Default, TestVarsType.RangeString, "38c4f4"),

            new(CrcType.Crc24, Crc24Preset.Ble, TestVarsType.TestString, "ffa950"),
            new(CrcType.Crc24, Crc24Preset.Ble, TestVarsType.RangeString, "acab7d"),

            new(CrcType.Crc24, Crc24Preset.FlexRayA, TestVarsType.TestString, "2c70f2"),
            new(CrcType.Crc24, Crc24Preset.FlexRayA, TestVarsType.RangeString, "294438"),

            new(CrcType.Crc24, Crc24Preset.FlexRayB, TestVarsType.TestString, "0e3a1d"),
            new(CrcType.Crc24, Crc24Preset.FlexRayB, TestVarsType.RangeString, "d5ee31"),

            new(CrcType.Crc24, Crc24Preset.Interlaken, TestVarsType.TestString, "5d5302"),
            new(CrcType.Crc24, Crc24Preset.Interlaken, TestVarsType.RangeString, "39d91d"),

            new(CrcType.Crc24, Crc24Preset.LteA, TestVarsType.TestString, "d62e8f"),
            new(CrcType.Crc24, Crc24Preset.LteA, TestVarsType.RangeString, "b1f403"),

            new(CrcType.Crc24, Crc24Preset.LteB, TestVarsType.TestString, "137ceb"),
            new(CrcType.Crc24, Crc24Preset.LteB, TestVarsType.RangeString, "da2736"),

            new(CrcType.Crc24, Crc24Preset.Os9, TestVarsType.TestString, "634135"),
            new(CrcType.Crc24, Crc24Preset.Os9, TestVarsType.RangeString, "b6660c"),

            #endregion

            #region CRC-30 and CRC-31 (padded)

            new(CrcType.Crc30, Crc30Preset.Default, TestVarsType.TestString, "36037067"),
            new(CrcType.Crc30, Crc30Preset.Default, TestVarsType.RangeString, "18b1ef87"),

            new(CrcType.Crc31, Crc31Preset.Default, TestVarsType.TestString, "1a76718d"),
            new(CrcType.Crc31, Crc31Preset.Default, TestVarsType.RangeString, "37e0c69c"),

            #endregion

            #region CRC-32

            new(CrcType.Crc32, Crc32Preset.Default, TestVarsType.TestString, "784dd132"),
            new(CrcType.Crc32, Crc32Preset.Default, TestVarsType.RangeString, "7ad6d652"),

            new(CrcType.Crc32, Crc32Preset.Autosar, TestVarsType.TestString, "d8132eb0"),
            new(CrcType.Crc32, Crc32Preset.Autosar, TestVarsType.RangeString, "a628d0d8"),

            new(CrcType.Crc32, Crc32Preset.CdRomEdc, TestVarsType.TestString, "2d8195d8"),
            new(CrcType.Crc32, Crc32Preset.CdRomEdc, TestVarsType.RangeString, "901cf0dd"),

            new(CrcType.Crc32, Crc32Preset.Q, TestVarsType.TestString, "1fc717d7"),
            new(CrcType.Crc32, Crc32Preset.Q, TestVarsType.RangeString, "95d827df"),

            new(CrcType.Crc32, Crc32Preset.BZip2, TestVarsType.TestString, "d962895d"),
            new(CrcType.Crc32, Crc32Preset.BZip2, TestVarsType.RangeString, "45cbc18b"),

            new(CrcType.Crc32, Crc32Preset.C, TestVarsType.TestString, "5185664b"),
            new(CrcType.Crc32, Crc32Preset.C, TestVarsType.RangeString, "09cd6072"),

            new(CrcType.Crc32, Crc32Preset.D, TestVarsType.TestString, "d1ebff71"),
            new(CrcType.Crc32, Crc32Preset.D, TestVarsType.RangeString, "ab5be79c"),

            new(CrcType.Crc32, Crc32Preset.JamCrc, TestVarsType.TestString, "87b22ecd"),
            new(CrcType.Crc32, Crc32Preset.JamCrc, TestVarsType.RangeString, "852929ad"),

            new(CrcType.Crc32, Crc32Preset.Mpeg2, TestVarsType.TestString, "269d76a2"),
            new(CrcType.Crc32, Crc32Preset.Mpeg2, TestVarsType.RangeString, "ba343e74"),

            new(CrcType.Crc32, Crc32Preset.Posix, TestVarsType.TestString, "1e665426"),
            new(CrcType.Crc32, Crc32Preset.Posix, TestVarsType.RangeString, "d17dacbe"),

            new(CrcType.Crc32, Crc32Preset.Xfer, TestVarsType.TestString, "b006037d"),
            new(CrcType.Crc32, Crc32Preset.Xfer, TestVarsType.RangeString, "7964bec3"),

            #endregion

            #region CRC-40

            new(CrcType.Crc40, Crc40Preset.Default, TestVarsType.TestString, "10df47b471"),
            new(CrcType.Crc40, Crc40Preset.Default, TestVarsType.RangeString, "f46d283fad"),

            #endregion

            #region CRC-64

            new(CrcType.Crc64, Crc64Preset.Default, TestVarsType.TestString, "02f6563f4a3751ff"),
            new(CrcType.Crc64, Crc64Preset.Default, TestVarsType.RangeString, "59d3e35dccce4de9"),

            new(CrcType.Crc64, Crc64Preset.We, TestVarsType.TestString, "d00f8e47e656f4d0"),
            new(CrcType.Crc64, Crc64Preset.We, TestVarsType.RangeString, "eafb40d259d5882c"),

            new(CrcType.Crc64, Crc64Preset.Xz, TestVarsType.TestString, "6275e834da84732f"),
            new(CrcType.Crc64, Crc64Preset.Xz, TestVarsType.RangeString, "2472ea52fe9d7cf0"),

            new(CrcType.Crc64, Crc64Preset.GoIso, TestVarsType.TestString, "287c72fe50000000"),
            new(CrcType.Crc64, Crc64Preset.GoIso, TestVarsType.RangeString, "e6d3b62e3b9bd7f1"),

            #endregion

            #region CRC-82 (padded)

            new(CrcType.Crc82, Crc82Preset.Default, TestVarsType.TestString, "016348ec7ea7f602abd024"),
            new(CrcType.Crc82, Crc82Preset.Default, TestVarsType.RangeString, "03dff868d831e5a22b515a"),

            #endregion
        };

        [Test]
        [TestCaseSource(nameof(PresetTestData))]
        [Category("Method")]
        public void InstanceEncrypt(CrcType crcType, Enum algorithm, TestVarsType varsType, string expectedHash)
        {
            dynamic instance = crcType switch
            {
                CrcType.Crc16 => new CrcCustom<ushort>(CrcPreset.GetConfig((Crc16Preset)algorithm)),
                CrcType.Crc17 => new CrcCustom<uint>(CrcPreset.GetConfig((Crc17Preset)algorithm)),
                CrcType.Crc21 => new CrcCustom<uint>(CrcPreset.GetConfig((Crc21Preset)algorithm)),
                CrcType.Crc24 => new CrcCustom<uint>(CrcPreset.GetConfig((Crc24Preset)algorithm)),
                CrcType.Crc30 => new CrcCustom<uint>(CrcPreset.GetConfig((Crc30Preset)algorithm)),
                CrcType.Crc31 => new CrcCustom<uint>(CrcPreset.GetConfig((Crc31Preset)algorithm)),
                CrcType.Crc32 => new CrcCustom<uint>(CrcPreset.GetConfig((Crc32Preset)algorithm)),
                CrcType.Crc40 => new CrcCustom<ulong>(CrcPreset.GetConfig((Crc40Preset)algorithm)),
                CrcType.Crc64 => new CrcCustom<ulong>(CrcPreset.GetConfig((Crc64Preset)algorithm)),
                CrcType.Crc82 => new CrcCustom<BigInteger>(CrcPreset.GetConfig((Crc82Preset)algorithm)),
                _ => throw new ArgumentOutOfRangeException(nameof(crcType), crcType, null)
            };
            switch (varsType)
            {
                case TestVarsType.TestString:
                    instance.Encrypt(TestVars.TestStr);
                    break;
                case TestVarsType.RangeString:
                    instance.Encrypt(TestVars.RangeStr);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedHash, instance.Hash);
        }
    }
}
