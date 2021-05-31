namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Globalization;
    using System.Numerics;

    /// <summary>Specifies enumerated constants used to define an CRC-16 preset.</summary>
    public enum Crc16Preset
    {
        /// <summary>CRC-16/USB.</summary>
        /// <remarks>Equal to <see cref="Usb"/>.</remarks>
        Default,

        /// <summary>CRC-16/USB.</summary>
        /// <remarks>Equal to <see cref="Default"/>.</remarks>
        Usb = Default,

        /// <summary>CRC-16/A.</summary>
        A,

        /// <summary>CRC-16/ARC.</summary>
        Arc,

        /// <summary>CRC-16/AUG-CCITT.</summary>
        AugCcitt,

        /// <summary>CRC-16/BUYPASS.</summary>
        Buypass,

        /// <summary>CRC-16/CCITT-FALSE.</summary>
        CcittFalse,

        /// <summary>CRC-16/CDMA2000.</summary>
        Cdma2000,

        /// <summary>CRC-16/DDS-110.</summary>
        Dds110,

        /// <summary>CRC-16/DECT-R.</summary>
        DectR,

        /// <summary>CRC-16/DECT-X.</summary>
        DectX,

        /// <summary>CRC-16/DNP.</summary>
        Dnp,

        /// <summary>CRC-16/EN-13757.</summary>
        En13757,

        /// <summary>CRC-16/GENIBUS.</summary>
        Genibus,

        /// <summary>CRC-16/KERMIT.</summary>
        Kermit,

        /// <summary>CRC-16/MAXIM.</summary>
        Maxim,

        /// <summary>CRC-16/MCRF4XX.</summary>
        Mcrf4Xx,

        /// <summary>CRC-16/MODBUS.</summary>
        ModBus,

        /// <summary>CRC-16/RIELLO.</summary>
        Riello,

        /// <summary>CRC-16/T10-DIF.</summary>
        T10Dif,

        /// <summary>CRC-16/TELEDISK.</summary>
        TeleDisk,

        /// <summary>CRC-16/TMS37157.</summary>
        Tms37157,

        /// <summary>CRC-16/XMODEM.</summary>
        XModem,

        /// <summary>CRC-16/X-25.</summary>
        X25
    }

    /// <summary>Specifies enumerated constants used to define an CRC-17 preset.</summary>
    public enum Crc17Preset
    {
        /// <summary>CRC-17/CAN-FD.</summary>
        /// <remarks>Equal to <see cref="CanFd"/>.</remarks>
        Default,

        /// <summary>CRC-17/CAN-FD.</summary>
        /// <remarks>Equal to <see cref="Default"/>.</remarks>
        CanFd = Default
    }

    /// <summary>Specifies enumerated constants used to define an CRC-21 preset.</summary>
    public enum Crc21Preset
    {
        /// <summary>CRC-21/CAN-FD.</summary>
        /// <remarks>Equal to <see cref="CanFd"/>.</remarks>
        Default,

        /// <summary>CRC-21/CAN-FD.</summary>
        /// <remarks>Equal to <see cref="Default"/>.</remarks>
        CanFd = Default
    }

    /// <summary>Specifies enumerated constants used to define an CRC-24 preset.</summary>
    public enum Crc24Preset
    {
        /// <summary>CRC-24/OPENPGP.</summary>
        /// <remarks>Equal to <see cref="OpenPgp"/>.</remarks>
        Default,

        /// <summary>CRC-24/OPENPGP.</summary>
        /// <remarks>Equal to <see cref="Default"/>.</remarks>
        OpenPgp = Default,

        /// <summary>CRC-24/BLE.</summary>
        Ble,

        /// <summary>CRC-24/LTE-A.</summary>
        LteA,

        /// <summary>CRC-24/LTE-B.</summary>
        LteB,

        /// <summary>CRC-24/FLEXRAY-A.</summary>
        FlexRayA,

        /// <summary>CRC-24/FLEXRAY-B.</summary>
        FlexRayB,

        /// <summary>CRC-24/INTERLAKEN.</summary>
        Interlaken,

        /// <summary>CRC-24/OS-9.</summary>
        Os9
    }

    /// <summary>Specifies enumerated constants used to define an CRC-30 preset.</summary>
    public enum Crc30Preset
    {
        /// <summary>CRC-30/CDMA.</summary>
        /// <remarks>Equal to <see cref="Cdma"/>.</remarks>
        Default,

        /// <summary>CRC-30/CDMA.</summary>
        /// <remarks>Equal to <see cref="Default"/>.</remarks>
        Cdma = Default
    }

    /// <summary>Specifies enumerated constants used to define an CRC-31 preset.</summary>
    public enum Crc31Preset
    {
        /// <summary>CRC-31/PHILIPS.</summary>
        /// <remarks>Equal to <see cref="Philips"/>.</remarks>
        Default,

        /// <summary>CRC-31/PHILIPS.</summary>
        /// <remarks>Equal to <see cref="Default"/>.</remarks>
        Philips = Default
    }

    /// <summary>Specifies enumerated constants used to define an CRC-32 preset.</summary>
    public enum Crc32Preset
    {
        /// <summary>CRC-32/ISO-HDLC.</summary>
        /// <remarks>Equal to <see cref="Adccp"/>, <see cref="IsoHdlc"/>, <see cref="PkZip"/>, <see cref="V24"/> and <see cref="Xz"/>.</remarks>
        Default,

        /// <summary>CRC-32/ADCCP.</summary>
        /// <remarks>Equal to <see cref="Default"/>, <see cref="PkZip"/>, <see cref="V24"/> and <see cref="Xz"/>.</remarks>
        Adccp = Default,

        /// <summary>CRC-32/ISO-HDLC.</summary>
        /// <remarks>Equal to <see cref="Default"/>, <see cref="Adccp"/>, <see cref="PkZip"/>, <see cref="V24"/> and <see cref="Xz"/>.</remarks>
        IsoHdlc = Default,

        /// <summary>CRC-32/PKZip.</summary>
        /// <remarks>Equal to <see cref="Default"/>, <see cref="Adccp"/>, <see cref="IsoHdlc"/>, <see cref="V24"/> and <see cref="Xz"/>.</remarks>
        PkZip = Default,

        /// <summary>CRC-32/V-24.</summary>
        /// <remarks>Equal to <see cref="Default"/>, <see cref="Adccp"/>, <see cref="IsoHdlc"/>, <see cref="PkZip"/> and <see cref="Xz"/>.</remarks>
        V24 = Default,

        /// <summary>CRC-32/XZ.</summary>
        /// <remarks>Equal to <see cref="Default"/>, <see cref="Adccp"/>, <see cref="IsoHdlc"/>, <see cref="PkZip"/> and <see cref="V24"/>.</remarks>
        Xz = Default,

        /// <summary>CRC-32/AUTOSAR.</summary>
        Autosar,

        /// <summary>CRC-32/CD-ROM-EDC.</summary>
        CdRomEdc,

        /// <summary>CRC-32/Q.</summary>
        /// <remarks>Equal to <see cref="Aixm"/>.</remarks>
        Q,

        /// <summary>CRC-32/AIXM.</summary>
        /// <remarks>Equal to <see cref="Q"/>.</remarks>
        Aixm = Q,

        /// <summary>CRC-32/BZIP2.</summary>
        /// <remarks>Equal to <see cref="AaL5"/>, <see cref="DectB"/> and <see cref="BCrc"/>.</remarks>
        BZip2,

        /// <summary>CRC-32/AAL5.</summary>
        /// <remarks>Equal to <see cref="BZip2"/>, <see cref="DectB"/> and <see cref="BCrc"/>.</remarks>
        AaL5 = BZip2,

        /// <summary>CRC-32/DECT-B.</summary>
        /// <remarks>Equal to <see cref="AaL5"/>, <see cref="BZip2"/> and <see cref="BCrc"/>.</remarks>
        DectB = BZip2,

        /// <summary>CRC-32/B-CRC.</summary>
        /// <remarks>Equal to <see cref="AaL5"/>, <see cref="BZip2"/> and <see cref="DectB"/>.</remarks>
        BCrc = BZip2,

        /// <summary>CRC-32/C.</summary>
        /// <remarks>Equal to <see cref="Base91C"/>, <see cref="Castagnoli"/>, <see cref="Interlaken"/> and <see cref="Iscsi"/>.</remarks>
        C,

        /// <summary>CRC-32/BASE91-C.</summary>
        /// <remarks>Equal to <see cref="C"/>, <see cref="Castagnoli"/>, <see cref="Interlaken"/> and <see cref="Iscsi"/>.</remarks>
        Base91C = C,

        /// <summary>CRC-32/Castagnoli.</summary>
        /// <remarks>Equal to <see cref="Base91C"/>, <see cref="C"/>, <see cref="Interlaken"/> and <see cref="Iscsi"/>.</remarks>
        Castagnoli = C,

        /// <summary>CRC-32/Interlaken.</summary>
        /// <remarks>Equal to <see cref="Base91C"/>, <see cref="C"/>, <see cref="Castagnoli"/> and <see cref="Iscsi"/>.</remarks>
        Interlaken = C,

        /// <summary>CRC-32/ISCSI.</summary>
        /// <remarks>Equal to <see cref="Base91C"/>, <see cref="C"/>, <see cref="Castagnoli"/> and <see cref="Interlaken"/>.</remarks>
        Iscsi = C,

        /// <summary>CRC-32/D.</summary>
        /// <remarks>Equal to <see cref="Base91D"/>.</remarks>
        D,

        /// <summary>CRC-32/BASE91-D.</summary>
        /// <remarks>Equal to <see cref="D"/>.</remarks>
        Base91D = D,

        /// <summary>CRC-32/JAMCRC.</summary>
        JamCrc,

        /// <summary>CRC-32/MPEG-2.</summary>
        Mpeg2,

        /// <summary>CRC-32/POSIX.</summary>
        /// <remarks>Equal to <see cref="CkSum"/>.</remarks>
        Posix,

        /// <summary>CRC-32/CKSUM.</summary>
        /// <remarks>Equal to <see cref="Posix"/>.</remarks>
        CkSum = Posix,

        /// <summary>CRC-32/XFER.</summary>
        Xfer
    }

    /// <summary>Specifies enumerated constants used to define an CRC-40 preset.</summary>
    public enum Crc40Preset
    {
        /// <summary>CRC-40/GSM.</summary>
        /// <remarks>Equal to <see cref="Gsm"/>.</remarks>
        Default,

        /// <summary>CRC-40/GSM.</summary>
        /// <remarks>Equal to <see cref="Default"/>.</remarks>
        Gsm = Default
    }

    /// <summary>Specifies enumerated constants used to define an CRC-64 preset.</summary>
    public enum Crc64Preset
    {
        /// <summary>CRC-64/ECMA-182.</summary>
        /// <remarks>Equal to <see cref="Ecma"/>.</remarks>
        Default,

        /// <summary>CRC-64/ECMA-182.</summary>
        /// <remarks>Equal to <see cref="Default"/>.</remarks>
        Ecma = Default,

        /// <summary>CRC-64/WE.</summary>
        We,

        /// <summary>CRC-64/XZ.</summary>
        /// <remarks>Equal to <see cref="GoEcma"/>.</remarks>
        Xz,

        /// <summary>CRC-64/GO-ECMA.</summary>
        /// <remarks>Equal to <see cref="Xz"/>.</remarks>
        GoEcma = Xz,

        /// <summary>CRC-64/GO-ISO.</summary>
        GoIso
    }

    /// <summary>Specifies enumerated constants used to define an CRC-82 preset.</summary>
    public enum Crc82Preset
    {
        /// <summary>CRC-82/DARC.</summary>
        /// <remarks>Equal to <see cref="Darc"/>.</remarks>
        Default,

        /// <summary>CRC-82/DARC.</summary>
        /// <remarks>Equal to <see cref="Default"/>.</remarks>
        Darc = Default
    }

    /// <summary>Provides static functions for loading preset <see cref="CrcConfig{TValue}"/> structures.</summary>
    public static class CrcPreset
    {
        /// <summary>Loads a predefined CRC-16 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-16 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static CrcConfig<ushort> GetConfig(Crc16Preset preset) =>
            preset switch
            {
                Crc16Preset.Default =>
                    new(16, 0xb4c8, 0xa001, 0xffff, true, true, 0xffff),

                Crc16Preset.A =>
                    new(16, 0xbf05, 0x8408, 0x6363, true, true),

                Crc16Preset.Arc =>
                    new(16, 0xbb3d, 0xa001, default, true, true),

                Crc16Preset.AugCcitt =>
                    new(16, 0xe5cc, 0x1021, 0x1d0f),

                Crc16Preset.Buypass =>
                    new(16, 0xfee8, 0x8005),

                Crc16Preset.CcittFalse =>
                    new(16, 0x29b1, 0x1021, 0xffff),

                Crc16Preset.Cdma2000 =>
                    new(16, 0x4c06, 0xc867, 0xffff),

                Crc16Preset.Dds110 =>
                    new(16, 0x9ecf, 0x8005, 0x800d),

                Crc16Preset.DectR =>
                    new(16, 0x007e, 0x0589, default, false, false, 0x0001),

                Crc16Preset.DectX =>
                    new(16, 0x007f, 0x0589),

                Crc16Preset.Dnp =>
                    new(16, 0xea82, 0xa6bc, default, true, true, 0xffff),

                Crc16Preset.En13757 =>
                    new(16, 0xc2b7, 0x3d65, default, false, false, 0xffff),

                Crc16Preset.Genibus =>
                    new(16, 0xd64e, 0x1021, 0xffff, false, false, 0xffff),

                Crc16Preset.Kermit =>
                    new(16, 0x2189, 0x8408, default, true, true),

                Crc16Preset.Maxim =>
                    new(16, 0x44c2, 0xa001, default, true, true, 0xffff),

                Crc16Preset.Mcrf4Xx =>
                    new(16, 0x6f91, 0x8408, 0xffff, true, true),

                Crc16Preset.ModBus =>
                    new(16, 0x4b37, 0xa001, 0xffff, true, true),

                Crc16Preset.Riello =>
                    new(16, 0x63d0, 0x8408, 0x554d, true, true),

                Crc16Preset.T10Dif =>
                    new(16, 0xd0db, 0x8bb7),

                Crc16Preset.TeleDisk =>
                    new(16, 0x0fb3, 0xa097),

                Crc16Preset.Tms37157 =>
                    new(16, 0x26b1, 0x8408, 0x3791, true, true),

                Crc16Preset.X25 =>
                    new(16, 0x906e, 0x8408, 0xffff, true, true, 0xffff),

                Crc16Preset.XModem =>
                    new(16, 0x31c3, 0x1021),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-17 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-17 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static CrcConfig<uint> GetConfig(Crc17Preset preset) =>
            preset switch
            {
                Crc17Preset.Default =>
                    new(17, 0x04f03u, 0x1685bu, default, false, false, default, 0x33ffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-21 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-21 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static CrcConfig<uint> GetConfig(Crc21Preset preset) =>
            preset switch
            {
                Crc21Preset.Default =>
                    new(21, 0x0ed841u, 0x102899u, default, false, false, default, 0x1fffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-24 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-24 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static CrcConfig<uint> GetConfig(Crc24Preset preset) =>
            preset switch
            {
                Crc24Preset.Default =>
                    new(24, 0x21cf02u, 0x864cfbu, 0xb704ceu),

                Crc24Preset.Ble =>
                    new(24, 0xc25a56u, 0xda6000u, 0xaaaaaau, true, true),

                Crc24Preset.LteA =>
                    new(24, 0xcde703u, 0x864cfbu),

                Crc24Preset.LteB =>
                    new(24, 0x23ef52u, 0x800063u),

                Crc24Preset.FlexRayA =>
                    new(24, 0x7979bdu, 0x5d6dcbu, 0xfedcbau),

                Crc24Preset.FlexRayB =>
                    new(24, 0x1f23b8u, 0x5d6dcbu, 0xabcdefu),

                Crc24Preset.Interlaken =>
                    new(24, 0xb4f3e6u, 0x328b63u, 0xffffffu, false, false, 0xffffffu),

                Crc24Preset.Os9 =>
                    new(24, 0x200fa5u, 0x800063u, 0xffffffu, false, false, 0xffffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-30 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-30 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static CrcConfig<uint> GetConfig(Crc30Preset preset) =>
            preset switch
            {
                Crc30Preset.Default =>
                    new(30, 0x04c34abfu, 0x2030b9c7u, 0x3fffffffu, false, false, 0x3fffffffu, 0x3fffffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-31 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-31 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static CrcConfig<uint> GetConfig(Crc31Preset preset) =>
            preset switch
            {
                Crc31Preset.Default =>
                    new(31, 0x0ce9e46cu, 0x4c11db7u, 0x7fffffffu, false, false, 0x7fffffffu, 0x7fffffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-32 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-32 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static CrcConfig<uint> GetConfig(Crc32Preset preset) =>
            preset switch
            {
                Crc32Preset.Default =>
                    new(32, 0xcbf43926u, 0xedb88320u, 0xffffffffu, true, true, 0xffffffffu),

                Crc32Preset.Autosar =>
                    new(32, 0x1697d06au, 0xc8df352fu, 0xffffffffu, true, true, 0xffffffffu),

                Crc32Preset.CdRomEdc =>
                    new(32, 0x6ec2edc4u, 0xd8018001u, default, true, true),

                Crc32Preset.Q =>
                    new(32, 0x3010bf7fu, 0x814141abu),

                Crc32Preset.BZip2 =>
                    new(32, 0xfc891918u, 0x04c11db7u, 0xffffffffu, false, false, 0xffffffffu),

                Crc32Preset.C =>
                    new(32, 0xe3069283u, 0x82f63b78u, 0xffffffffu, true, true, 0xffffffffu),

                Crc32Preset.D =>
                    new(32, 0x87315576u, 0xd419cc15u, 0xffffffffu, true, true, 0xffffffffu),

                Crc32Preset.JamCrc =>
                    new(32, 0x340bc6d9u, 0xedb88320u, 0xffffffffu, true, true),

                Crc32Preset.Mpeg2 =>
                    new(32, 0x0376e6e7u, 0x04c11db7u, 0xffffffffu),

                Crc32Preset.Posix =>
                    new(32, 0x765e7680u, 0x04c11db7u, default, false, false, 0xffffffffu),

                Crc32Preset.Xfer =>
                    new(32, 0xbd0be338u, 0x000000afu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-40 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-40 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static CrcConfig<ulong> GetConfig(Crc40Preset preset) =>
            preset switch
            {
                Crc40Preset.Default =>
                    new(40, 0xd4164fc646uL, 0x0004820009uL, default, false, false, 0xffffffffffuL),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-64 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-64 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static CrcConfig<ulong> GetConfig(Crc64Preset preset) =>
            preset switch
            {
                Crc64Preset.Default =>
                    new(64, 0x6c40df5f0b497347uL, 0x42f0e1eba9ea3693uL),

                Crc64Preset.We =>
                    new(64, 0x62ec59e3f1a4f00auL, 0x42f0e1eba9ea3693uL, 0xffffffffffffffffuL, false, false, 0xffffffffffffffffuL),

                Crc64Preset.Xz =>
                    new(64, 0x995dc9bbdf1939fauL, 0xc96c5795d7870f42uL, 0xffffffffffffffffuL, true, true, 0xffffffffffffffffuL),

                Crc64Preset.GoIso =>
                    new(64, 0xb90956c775a41001uL, 0xd800000000000000uL, 0xffffffffffffffffuL, true, true, 0xffffffffffffffffuL),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-82 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-64 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static CrcConfig<BigInteger> GetConfig(Crc82Preset preset) =>
            preset switch
            {
                Crc82Preset.Default =>
                    new(82,
                        BigInteger.Parse("09ea83f625023801fd612", NumberStyles.AllowHexSpecifier),
                        BigInteger.Parse("220808a00a2022200c430", NumberStyles.AllowHexSpecifier), default, true, true, default,
                        BigInteger.Parse("3ffffffffffffffffffff", NumberStyles.AllowHexSpecifier)),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
    }
}
