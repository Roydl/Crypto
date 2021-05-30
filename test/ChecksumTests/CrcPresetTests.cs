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
        public sealed class CrcCustom<T> : ChecksumAlgorithm<CrcCustom<T>> where T : IFormattable
        {
            private CrcConfig<T> Current { get; }

            public CrcCustom(CrcConfig<T> config) : base(config.Bits) =>
                Current = config;

            public CrcCustom(int bits, T poly, T init = default, bool refIn = false, bool refOut = false, T xorOut = default) : base(bits) =>
                Current = new CrcConfig<T>(bits, poly, init, refIn, refOut, xorOut);

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

        public enum CrcCustomPreset
        {
            #region CRC-8 to CRC-15

            Crc08,
            Crc10,
            Crc11,
            Crc12Dect,
            Crc13Bbc,
            Crc14Darc,
            Crc15,
            Crc15Mpt1327,

            #endregion

            #region CRC-16

            Crc16,
            Crc16A,
            Crc16Arc,
            Crc16AugCcitt,
            Crc16Buypass,
            Crc16CcittFalse,
            Crc16Cdma2000,
            Crc16Dds110,
            Crc16DectR,
            Crc16DectX,
            Crc16Dnp,
            Crc16En13757,
            Crc16Genibus,
            Crc16Kermit,
            Crc16Maxim,
            Crc16Mcrf4Xx,
            Crc16ModBus,
            Crc16Riello,
            Crc16T10Dif,
            Crc16TeleDisk,
            Crc16Tms37157,
            Crc16X25,
            Crc16XModem,

            #endregion

            #region CRC-17 and CRC-21

            Crc17,
            Crc21,

            #endregion

            #region CRC-24

            Crc24,
            Crc24Ble,
            Crc24LteA,
            Crc24LteB,
            Crc24FlexRayA,
            Crc24FlexRayB,
            Crc24Interlaken,
            Crc24Os9,

            #endregion

            #region CRC-30 and CRC-31

            Crc30,
            Crc31Philips,

            #endregion

            #region CRC-32

            Crc32,
            Crc32Autosar,
            Crc32CdRomEdc,
            Crc32Q,
            Crc32Bzip2,
            Crc32C,
            Crc32D,
            Crc32Jam,
            Crc32Mpeg2,
            Crc32Posix,
            Crc32Xfer,

            #endregion

            #region CRC-40

            Crc40,

            #endregion

            #region CRC-64

            Crc64,
            Crc64We,
            Crc64Xz,
            Crc64GoIso,

            #endregion

            #region CRC-82

            Crc82

            #endregion
        }

        private static readonly TestCaseData[] TestData =
        {
            #region CRC-8 to CRC-15

            new(CrcCustomPreset.Crc08, TestVarsType.TestString, "77"),
            new(CrcCustomPreset.Crc08, TestVarsType.RangeString, "a8"),

            new(CrcCustomPreset.Crc10, TestVarsType.TestString, "f030"),
            new(CrcCustomPreset.Crc10, TestVarsType.RangeString, "36f5"),

            new(CrcCustomPreset.Crc11, TestVarsType.TestString, "cbbf"),
            new(CrcCustomPreset.Crc11, TestVarsType.RangeString, "350f"),

            new(CrcCustomPreset.Crc12Dect, TestVarsType.TestString, "5b5e"),
            new(CrcCustomPreset.Crc12Dect, TestVarsType.RangeString, "c25c"),

            new(CrcCustomPreset.Crc13Bbc, TestVarsType.TestString, "6566"),
            new(CrcCustomPreset.Crc13Bbc, TestVarsType.RangeString, "1672"),

            new(CrcCustomPreset.Crc14Darc, TestVarsType.TestString, "30aa"),
            new(CrcCustomPreset.Crc14Darc, TestVarsType.RangeString, "30d9"),

            new(CrcCustomPreset.Crc15, TestVarsType.TestString, "ab53"),
            new(CrcCustomPreset.Crc15, TestVarsType.RangeString, "77dc"),

            new(CrcCustomPreset.Crc15Mpt1327, TestVarsType.TestString, "920f"),
            new(CrcCustomPreset.Crc15Mpt1327, TestVarsType.RangeString, "4bf8"),

            #endregion

            #region CRC-16

            new(CrcCustomPreset.Crc16, TestVarsType.TestString, "e3da"),
            new(CrcCustomPreset.Crc16, TestVarsType.RangeString, "9354"),

            new(CrcCustomPreset.Crc16A, TestVarsType.TestString, "2205"),
            new(CrcCustomPreset.Crc16A, TestVarsType.RangeString, "d4c4"),

            new(CrcCustomPreset.Crc16Arc, TestVarsType.TestString, "3825"),
            new(CrcCustomPreset.Crc16Arc, TestVarsType.RangeString, "30f1"),

            new(CrcCustomPreset.Crc16AugCcitt, TestVarsType.TestString, "a258"),
            new(CrcCustomPreset.Crc16AugCcitt, TestVarsType.RangeString, "113b"),

            new(CrcCustomPreset.Crc16Buypass, TestVarsType.TestString, "3ce2"),
            new(CrcCustomPreset.Crc16Buypass, TestVarsType.RangeString, "7197"),

            new(CrcCustomPreset.Crc16CcittFalse, TestVarsType.TestString, "2888"),
            new(CrcCustomPreset.Crc16CcittFalse, TestVarsType.RangeString, "314d"),

            new(CrcCustomPreset.Crc16Cdma2000, TestVarsType.TestString, "134b"),
            new(CrcCustomPreset.Crc16Cdma2000, TestVarsType.RangeString, "023b"),

            new(CrcCustomPreset.Crc16Dds110, TestVarsType.TestString, "3c3a"),
            new(CrcCustomPreset.Crc16Dds110, TestVarsType.RangeString, "2d0e"),

            new(CrcCustomPreset.Crc16DectR, TestVarsType.TestString, "db7a"),
            new(CrcCustomPreset.Crc16DectR, TestVarsType.RangeString, "c7ab"),

            new(CrcCustomPreset.Crc16DectX, TestVarsType.TestString, "db7b"),
            new(CrcCustomPreset.Crc16DectX, TestVarsType.RangeString, "c7aa"),

            new(CrcCustomPreset.Crc16Dnp, TestVarsType.TestString, "b742"),
            new(CrcCustomPreset.Crc16Dnp, TestVarsType.RangeString, "8892"),

            new(CrcCustomPreset.Crc16En13757, TestVarsType.TestString, "f58d"),
            new(CrcCustomPreset.Crc16En13757, TestVarsType.RangeString, "7bae"),

            new(CrcCustomPreset.Crc16Genibus, TestVarsType.TestString, "d777"),
            new(CrcCustomPreset.Crc16Genibus, TestVarsType.RangeString, "ceb2"),

            new(CrcCustomPreset.Crc16Kermit, TestVarsType.TestString, "7405"),
            new(CrcCustomPreset.Crc16Kermit, TestVarsType.RangeString, "b7d9"),

            new(CrcCustomPreset.Crc16Maxim, TestVarsType.TestString, "c7da"),
            new(CrcCustomPreset.Crc16Maxim, TestVarsType.RangeString, "cf0e"),

            new(CrcCustomPreset.Crc16Mcrf4Xx, TestVarsType.TestString, "7724"),
            new(CrcCustomPreset.Crc16Mcrf4Xx, TestVarsType.RangeString, "18ea"),

            new(CrcCustomPreset.Crc16ModBus, TestVarsType.TestString, "1c25"),
            new(CrcCustomPreset.Crc16ModBus, TestVarsType.RangeString, "6cab"),

            new(CrcCustomPreset.Crc16Riello, TestVarsType.TestString, "5363"),
            new(CrcCustomPreset.Crc16Riello, TestVarsType.RangeString, "bc78"),

            new(CrcCustomPreset.Crc16T10Dif, TestVarsType.TestString, "17a1"),
            new(CrcCustomPreset.Crc16T10Dif, TestVarsType.RangeString, "d71a"),

            new(CrcCustomPreset.Crc16TeleDisk, TestVarsType.TestString, "f6ca"),
            new(CrcCustomPreset.Crc16TeleDisk, TestVarsType.RangeString, "48da"),

            new(CrcCustomPreset.Crc16Tms37157, TestVarsType.TestString, "8cda"),
            new(CrcCustomPreset.Crc16Tms37157, TestVarsType.RangeString, "e3ed"),

            new(CrcCustomPreset.Crc16X25, TestVarsType.TestString, "88db"),
            new(CrcCustomPreset.Crc16X25, TestVarsType.RangeString, "e715"),

            new(CrcCustomPreset.Crc16XModem, TestVarsType.TestString, "ac48"),
            new(CrcCustomPreset.Crc16XModem, TestVarsType.RangeString, "fdb8"),

            #endregion

            #region CRC-17 and CRC-21

            new(CrcCustomPreset.Crc17, TestVarsType.TestString, "c6c38d"),
            new(CrcCustomPreset.Crc17, TestVarsType.RangeString, "f582d1"),

            new(CrcCustomPreset.Crc21, TestVarsType.TestString, "d28a0d"),
            new(CrcCustomPreset.Crc21, TestVarsType.RangeString, "d6c0c0"),

            #endregion

            #region CRC-24

            new(CrcCustomPreset.Crc24, TestVarsType.TestString, "20777c"),
            new(CrcCustomPreset.Crc24, TestVarsType.RangeString, "38c4f4"),

            new(CrcCustomPreset.Crc24Ble, TestVarsType.TestString, "ffa950"),
            new(CrcCustomPreset.Crc24Ble, TestVarsType.RangeString, "acab7d"),

            new(CrcCustomPreset.Crc24FlexRayA, TestVarsType.TestString, "2c70f2"),
            new(CrcCustomPreset.Crc24FlexRayA, TestVarsType.RangeString, "294438"),

            new(CrcCustomPreset.Crc24FlexRayB, TestVarsType.TestString, "0e3a1d"),
            new(CrcCustomPreset.Crc24FlexRayB, TestVarsType.RangeString, "d5ee31"),

            new(CrcCustomPreset.Crc24Interlaken, TestVarsType.TestString, "a2acfd"),
            new(CrcCustomPreset.Crc24Interlaken, TestVarsType.RangeString, "c626e2"),

            new(CrcCustomPreset.Crc24LteA, TestVarsType.TestString, "d62e8f"),
            new(CrcCustomPreset.Crc24LteA, TestVarsType.RangeString, "b1f403"),

            new(CrcCustomPreset.Crc24LteB, TestVarsType.TestString, "137ceb"),
            new(CrcCustomPreset.Crc24LteB, TestVarsType.RangeString, "da2736"),

            new(CrcCustomPreset.Crc24Os9, TestVarsType.TestString, "9cbeca"),
            new(CrcCustomPreset.Crc24Os9, TestVarsType.RangeString, "4999f3"),

            #endregion

            #region CRC-30 and CRC-31

            new(CrcCustomPreset.Crc30, TestVarsType.TestString, "09fc8f98"),
            new(CrcCustomPreset.Crc30, TestVarsType.RangeString, "a74e1078"),

            new(CrcCustomPreset.Crc31Philips, TestVarsType.TestString, "1a76718d"),
            new(CrcCustomPreset.Crc31Philips, TestVarsType.RangeString, "37e0c69c"),

            #endregion

            #region CRC-32

            new(CrcCustomPreset.Crc32, TestVarsType.TestString, "784dd132"),
            new(CrcCustomPreset.Crc32, TestVarsType.RangeString, "7ad6d652"),

            new(CrcCustomPreset.Crc32Autosar, TestVarsType.TestString, "d8132eb0"),
            new(CrcCustomPreset.Crc32Autosar, TestVarsType.RangeString, "a628d0d8"),

            new(CrcCustomPreset.Crc32CdRomEdc, TestVarsType.TestString, "2d8195d8"),
            new(CrcCustomPreset.Crc32CdRomEdc, TestVarsType.RangeString, "901cf0dd"),

            new(CrcCustomPreset.Crc32Q, TestVarsType.TestString, "1fc717d7"),
            new(CrcCustomPreset.Crc32Q, TestVarsType.RangeString, "95d827df"),

            new(CrcCustomPreset.Crc32Bzip2, TestVarsType.TestString, "d962895d"),
            new(CrcCustomPreset.Crc32Bzip2, TestVarsType.RangeString, "45cbc18b"),

            new(CrcCustomPreset.Crc32C, TestVarsType.TestString, "5185664b"),
            new(CrcCustomPreset.Crc32C, TestVarsType.RangeString, "09cd6072"),

            new(CrcCustomPreset.Crc32D, TestVarsType.TestString, "d1ebff71"),
            new(CrcCustomPreset.Crc32D, TestVarsType.RangeString, "ab5be79c"),

            new(CrcCustomPreset.Crc32Jam, TestVarsType.TestString, "87b22ecd"),
            new(CrcCustomPreset.Crc32Jam, TestVarsType.RangeString, "852929ad"),

            new(CrcCustomPreset.Crc32Mpeg2, TestVarsType.TestString, "269d76a2"),
            new(CrcCustomPreset.Crc32Mpeg2, TestVarsType.RangeString, "ba343e74"),

            new(CrcCustomPreset.Crc32Posix, TestVarsType.TestString, "1e665426"),
            new(CrcCustomPreset.Crc32Posix, TestVarsType.RangeString, "d17dacbe"),

            new(CrcCustomPreset.Crc32Xfer, TestVarsType.TestString, "b006037d"),
            new(CrcCustomPreset.Crc32Xfer, TestVarsType.RangeString, "7964bec3"),

            #endregion

            #region CRC-40

            new(CrcCustomPreset.Crc40, TestVarsType.TestString, "10df47b471"),
            new(CrcCustomPreset.Crc40, TestVarsType.RangeString, "f46d283fad"),

            #endregion

            #region CRC-64

            new(CrcCustomPreset.Crc64, TestVarsType.TestString, "02f6563f4a3751ff"),
            new(CrcCustomPreset.Crc64, TestVarsType.RangeString, "59d3e35dccce4de9"),

            new(CrcCustomPreset.Crc64We, TestVarsType.TestString, "d00f8e47e656f4d0"),
            new(CrcCustomPreset.Crc64We, TestVarsType.RangeString, "eafb40d259d5882c"),

            new(CrcCustomPreset.Crc64Xz, TestVarsType.TestString, "6275e834da84732f"),
            new(CrcCustomPreset.Crc64Xz, TestVarsType.RangeString, "2472ea52fe9d7cf0"),

            new(CrcCustomPreset.Crc64GoIso, TestVarsType.TestString, "287c72fe50000000"),
            new(CrcCustomPreset.Crc64GoIso, TestVarsType.RangeString, "e6d3b62e3b9bd7f1"),

            #endregion

            #region CRC-82

            // ***WIP: Hashes still unconfirmed.
            new(CrcCustomPreset.Crc82, TestVarsType.TestString, "0003c97c1a9a92d954cf37"),
            new(CrcCustomPreset.Crc82, TestVarsType.RangeString, "0005d9765b4f8f041e644d")

            #endregion
        };

        private static object[] _instances;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instances = new object[Enum.GetNames(typeof(CrcCustomPreset)).Length];

            #region CRC-8 to CRC-15

            _instances[(int)CrcCustomPreset.Crc08] = new CrcCustom<byte>(8, 0x07);
            _instances[(int)CrcCustomPreset.Crc10] = new CrcCustom<ushort>(10, 0x233);
            _instances[(int)CrcCustomPreset.Crc11] = new CrcCustom<ushort>(11, 0x385, 0x1a);
            _instances[(int)CrcCustomPreset.Crc12Dect] = new CrcCustom<ushort>(12, 0x80f);
            _instances[(int)CrcCustomPreset.Crc13Bbc] = new CrcCustom<ushort>(13, 0x1cf5);
            _instances[(int)CrcCustomPreset.Crc14Darc] = new CrcCustom<ushort>(14, 0x2804, default, true, true);
            _instances[(int)CrcCustomPreset.Crc15] = new CrcCustom<ushort>(15, 0x4599);
            _instances[(int)CrcCustomPreset.Crc15Mpt1327] = new CrcCustom<ushort>(15, 0x6815, default, false, false, 0x01);

            #endregion

            #region CRC-16

            _instances[(int)CrcCustomPreset.Crc16] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Default));
            _instances[(int)CrcCustomPreset.Crc16A] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.A));
            _instances[(int)CrcCustomPreset.Crc16Arc] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Arc));
            _instances[(int)CrcCustomPreset.Crc16AugCcitt] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.AugCcitt));
            _instances[(int)CrcCustomPreset.Crc16Buypass] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Buypass));
            _instances[(int)CrcCustomPreset.Crc16CcittFalse] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.CcittFalse));
            _instances[(int)CrcCustomPreset.Crc16Cdma2000] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Cdma2000));
            _instances[(int)CrcCustomPreset.Crc16Dds110] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Dds110));
            _instances[(int)CrcCustomPreset.Crc16DectR] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.DectR));
            _instances[(int)CrcCustomPreset.Crc16DectX] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.DectX));
            _instances[(int)CrcCustomPreset.Crc16Dnp] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Dnp));
            _instances[(int)CrcCustomPreset.Crc16En13757] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.En13757));
            _instances[(int)CrcCustomPreset.Crc16Genibus] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Genibus));
            _instances[(int)CrcCustomPreset.Crc16Kermit] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Kermit));
            _instances[(int)CrcCustomPreset.Crc16Maxim] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Maxim));
            _instances[(int)CrcCustomPreset.Crc16Mcrf4Xx] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Mcrf4Xx));
            _instances[(int)CrcCustomPreset.Crc16ModBus] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.ModBus));
            _instances[(int)CrcCustomPreset.Crc16Riello] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Riello));
            _instances[(int)CrcCustomPreset.Crc16T10Dif] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.T10Dif));
            _instances[(int)CrcCustomPreset.Crc16TeleDisk] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.TeleDisk));
            _instances[(int)CrcCustomPreset.Crc16Tms37157] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.Tms37157));
            _instances[(int)CrcCustomPreset.Crc16X25] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.X25));
            _instances[(int)CrcCustomPreset.Crc16XModem] = new CrcCustom<ushort>(CrcPreset.GetConfig(Crc16Preset.XModem));

            #endregion

            #region CRC-17 and CRC-21

            _instances[(int)CrcCustomPreset.Crc17] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc17Preset.Default));
            _instances[(int)CrcCustomPreset.Crc21] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc21Preset.Default));

            #endregion

            #region CRC-24

            _instances[(int)CrcCustomPreset.Crc24] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc24Preset.Default));
            _instances[(int)CrcCustomPreset.Crc24Ble] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc24Preset.Ble));
            _instances[(int)CrcCustomPreset.Crc24FlexRayA] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc24Preset.FlexRayA));
            _instances[(int)CrcCustomPreset.Crc24FlexRayB] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc24Preset.FlexRayB));
            _instances[(int)CrcCustomPreset.Crc24Interlaken] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc24Preset.Interlaken));
            _instances[(int)CrcCustomPreset.Crc24LteA] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc24Preset.LteA));
            _instances[(int)CrcCustomPreset.Crc24LteB] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc24Preset.LteB));
            _instances[(int)CrcCustomPreset.Crc24Os9] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc24Preset.Os9));

            #endregion

            #region CRC-30 and CRC-31

            _instances[(int)CrcCustomPreset.Crc30] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc30Preset.Default));
            _instances[(int)CrcCustomPreset.Crc31Philips] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc31Preset.Default));

            #endregion

            #region CRC-32

            _instances[(int)CrcCustomPreset.Crc32] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc32Preset.Default));
            _instances[(int)CrcCustomPreset.Crc32Autosar] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc32Preset.Autosar));
            _instances[(int)CrcCustomPreset.Crc32CdRomEdc] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc32Preset.CdRomEdc));
            _instances[(int)CrcCustomPreset.Crc32Q] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc32Preset.Q));
            _instances[(int)CrcCustomPreset.Crc32Bzip2] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc32Preset.BZip2));
            _instances[(int)CrcCustomPreset.Crc32C] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc32Preset.C));
            _instances[(int)CrcCustomPreset.Crc32D] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc32Preset.D));
            _instances[(int)CrcCustomPreset.Crc32Jam] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc32Preset.JamCrc));
            _instances[(int)CrcCustomPreset.Crc32Mpeg2] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc32Preset.Mpeg2));
            _instances[(int)CrcCustomPreset.Crc32Posix] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc32Preset.Posix));
            _instances[(int)CrcCustomPreset.Crc32Xfer] = new CrcCustom<uint>(CrcPreset.GetConfig(Crc32Preset.Xfer));

            #endregion

            #region CRC-40

            _instances[(int)CrcCustomPreset.Crc40] = new CrcCustom<ulong>(CrcPreset.GetConfig(Crc40Preset.Default));

            #endregion

            #region CRC-64

            _instances[(int)CrcCustomPreset.Crc64] = new CrcCustom<ulong>(CrcPreset.GetConfig(Crc64Preset.Default));
            _instances[(int)CrcCustomPreset.Crc64We] = new CrcCustom<ulong>(CrcPreset.GetConfig(Crc64Preset.We));
            _instances[(int)CrcCustomPreset.Crc64Xz] = new CrcCustom<ulong>(CrcPreset.GetConfig(Crc64Preset.Xz));
            _instances[(int)CrcCustomPreset.Crc64GoIso] = new CrcCustom<ulong>(CrcPreset.GetConfig(Crc64Preset.GoIso));

            #endregion

            #region CRC-82

            _instances[(int)CrcCustomPreset.Crc82] = new CrcCustom<BigInteger>(CrcPreset.GetConfig(Crc82Preset.Default));

            #endregion
        }

        [Test]
        [TestCaseSource(nameof(TestData))]
        [Category("Method")]
        public void InstanceEncrypt(CrcCustomPreset algorithm, TestVarsType varsType, string expectedHash)
        {
            var instance = (dynamic)_instances[(int)algorithm];
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
