namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Numerics;
    using Internal;

    /// <summary>Specifies enumerated constants used to define an CRC-16 preset.</summary>
    public enum Crc16Preset
    {
        /// <summary>CRC-16.
        ///     <para><b>Alias:</b> ARC, IBM, LHA.</para>
        /// </summary>
        Default,

        /// <summary>CRC-16/A.</summary>
        A,

        /// <summary>CRC-16/BUYPASS.</summary>
        Buypass,

        /// <summary>CRC-16/CDMA2000.</summary>
        Cdma2000,

        /// <summary>CRC-16/CMS.</summary>
        Cms,

        /// <summary>CRC-16/DDS-110.</summary>
        Dds110,

        /// <summary>CRC-16/DECT-R.
        ///     <para><b>Alias:</b> R-CRC-16</para>
        /// </summary>
        DectR,

        /// <summary>CRC-16/DECT-X.
        ///     <para><b>Alias:</b> X-CRC-16</para>
        /// </summary>
        DectX,

        /// <summary>CRC-16/DNP.</summary>
        Dnp,

        /// <summary>CRC-16/EN-13757.</summary>
        En13757,

        /// <summary>CRC-16/GENIBUS.
        ///     <para><b>Alias:</b> DARC, EPC, EPC-C1G2, I-CODE</para>
        /// </summary>
        Genibus,

        /// <summary>CRC-16/GSM.</summary>
        Gsm,

        /// <summary>CRC-16/IBM-3740.
        ///     <para><b>Alias:</b> AUTOSAR, CCITT-FALSE</para>
        /// </summary>
        Ibm3740,

        /// <summary>CRC-16/IBM-SDLC.
        ///     <para><b>Alias:</b> ISO-HDLC, ISO-IEC-14443-3-B, CRC-B, X-25</para>
        /// </summary>
        IbmSdlc,

        /// <summary>CRC-16/KERMIT.</summary>
        Kermit,

        /// <summary>CRC-16/LJ1200.</summary>
        Lj1200,

        /// <summary>CRC-16/MAXIM.</summary>
        /// <para><b>Alias:</b> MAXIM-DOW</para>
        Maxim,

        /// <summary>CRC-16/MCRF4XX.</summary>
        Mcrf4Xx,

        /// <summary>CRC-16/MODBUS.</summary>
        ModBus,

        /// <summary>CRC-16/RIELLO.</summary>
        Riello,

        /// <summary>CRC-16/SPI-FUJITSU.
        ///     <para><b>Alias:</b> AUG-CCITT</para>
        /// </summary>
        SpiFujitsu,

        /// <summary>CRC-16/T10-DIF.</summary>
        T10Dif,

        /// <summary>CRC-16/TELEDISK.</summary>
        TeleDisk,

        /// <summary>CRC-16/TMS37157.</summary>
        Tms37157,

        /// <summary>CRC-16/USB.</summary>
        Usb,

        /// <summary>CRC-16/XMODEM.</summary>
        XModem
    }

    /// <summary>Specifies enumerated constants used to define an CRC-17 preset.</summary>
    public enum Crc17Preset
    {
        /// <summary>CRC-17.
        ///     <para><b>Alias:</b> CAN-FD.</para>
        /// </summary>
        Default
    }

    /// <summary>Specifies enumerated constants used to define an CRC-21 preset.</summary>
    public enum Crc21Preset
    {
        /// <summary>CRC-21.
        ///     <para><b>Alias:</b> CAN-FD.</para>
        /// </summary>
        Default
    }

    /// <summary>Specifies enumerated constants used to define an CRC-24 preset.</summary>
    public enum Crc24Preset
    {
        /// <summary>CRC-24.
        ///     <para><b>Alias:</b> OPENPGP.</para>
        /// </summary>
        Default,

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
        /// <summary>CRC-30.
        ///     <para><b>Alias:</b> CDMA.</para>
        /// </summary>
        Default
    }

    /// <summary>Specifies enumerated constants used to define an CRC-31 preset.</summary>
    public enum Crc31Preset
    {
        /// <summary>CRC-31.
        ///     <para><b>Alias:</b> PHILIPS.</para>
        /// </summary>
        Default
    }

    /// <summary>Specifies enumerated constants used to define an CRC-32 preset.</summary>
    public enum Crc32Preset
    {
        /// <summary>CRC-32/ISO-HDLC.
        ///     <para><b>Alias:</b> ADCCP, ISO-HDLC, PKZip, V-24, XZ.</para>
        /// </summary>
        Default,

        /// <summary>CRC-32/AUTOSAR.</summary>
        Autosar,

        /// <summary>CRC-32/CD-ROM-EDC.</summary>
        CdRomEdc,

        /// <summary>CRC-32/Q.
        ///     <para><b>Alias:</b> AIXM.</para>
        /// </summary>
        Q,

        /// <summary>CRC-32/BZIP2.
        ///     <para><b>Alias:</b> AAL5, DECT-B, B-CRC.</para>
        /// </summary>
        BZip2,

        /// <summary>CRC-32/C.
        ///     <para><b>Alias:</b> BASE91-C, Castagnoli, Interlaken, ISCSI.</para>
        /// </summary>
        C,

        /// <summary>CRC-32/D.
        ///     <para><b>Alias:</b> BASE91-D.</para>
        /// </summary>
        D,

        /// <summary>CRC-32/JAMCRC.</summary>
        JamCrc,

        /// <summary>CRC-32/MPEG-2.</summary>
        Mpeg2,

        /// <summary>CRC-32/POSIX.
        ///     <para><b>Alias:</b> CKSUM.</para>
        /// </summary>
        Posix,

        /// <summary>CRC-32/XFER.</summary>
        Xfer
    }

    /// <summary>Specifies enumerated constants used to define an CRC-40 preset.</summary>
    public enum Crc40Preset
    {
        /// <summary>CRC-40.
        ///     <para><b>Alias:</b> GSM.</para>
        /// </summary>
        Default
    }

    /// <summary>Specifies enumerated constants used to define an CRC-64 preset.</summary>
    public enum Crc64Preset
    {
        /// <summary>CRC-64.
        ///     <para><b>Alias:</b> ECMA-182.</para>
        /// </summary>
        Default,

        /// <summary>CRC-64/WE.</summary>
        We,

        /// <summary>CRC-64/XZ.
        ///     <para><b>Alias:</b> GO-ECMA.</para>
        /// </summary>
        Xz,

        /// <summary>CRC-64/GO-ISO.</summary>
        GoIso
    }

    /// <summary>Specifies enumerated constants used to define an CRC-82 preset.</summary>
    public enum Crc82Preset
    {
        /// <summary>CRC-82.
        ///     <para><b>Alias:</b> DARC.</para>
        /// </summary>
        Default
    }

    /// <summary>Provides static functions for loading preset <see cref="ICrcConfig{TValue}"/> structures.</summary>
    public static class CrcPreset
    {
        /// <summary>Loads a predefined CRC-16 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-16 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(Crc16Preset preset) =>
            preset switch
            {
                Crc16Preset.Default =>
                    new CrcConfig16(16, 0xbb3d, 0xa001, default, true, true),

                Crc16Preset.A =>
                    new CrcConfig16(16, 0xbf05, 0x8408, 0x6363, true, true),

                Crc16Preset.Buypass =>
                    new CrcConfig16(16, 0xfee8, 0x8005),

                Crc16Preset.Cdma2000 =>
                    new CrcConfig16(16, 0x4c06, 0xc867, 0xffff),

                Crc16Preset.Cms =>
                    new CrcConfig16(16, 0xaee7, 0x8005, 0xffff),

                Crc16Preset.Dds110 =>
                    new CrcConfig16(16, 0x9ecf, 0x8005, 0x800d),

                Crc16Preset.DectR =>
                    new CrcConfig16(16, 0x007e, 0x0589, default, false, false, 0x0001),

                Crc16Preset.DectX =>
                    new CrcConfig16(16, 0x007f, 0x0589),

                Crc16Preset.Dnp =>
                    new CrcConfig16(16, 0xea82, 0xa6bc, default, true, true, 0xffff),

                Crc16Preset.En13757 =>
                    new CrcConfig16(16, 0xc2b7, 0x3d65, default, false, false, 0xffff),

                Crc16Preset.Genibus =>
                    new CrcConfig16(16, 0xd64e, 0x1021, 0xffff, false, false, 0xffff),

                Crc16Preset.Gsm =>
                    new CrcConfig16(16, 0xce3c, 0x1021, default, false, false, 0xffff),

                Crc16Preset.Ibm3740 =>
                    new CrcConfig16(16, 0x29b1, 0x1021, 0xffff),

                Crc16Preset.IbmSdlc =>
                    new CrcConfig16(16, 0x906e, 0x8408, 0xffff, true, true, 0xffff),

                Crc16Preset.Kermit =>
                    new CrcConfig16(16, 0x2189, 0x8408, default, true, true),

                Crc16Preset.Lj1200 =>
                    new CrcConfig16(16, 0xbdf4, 0x6f63),

                Crc16Preset.Maxim =>
                    new CrcConfig16(16, 0x44c2, 0xa001, default, true, true, 0xffff),

                Crc16Preset.Mcrf4Xx =>
                    new CrcConfig16(16, 0x6f91, 0x8408, 0xffff, true, true),

                Crc16Preset.ModBus =>
                    new CrcConfig16(16, 0x4b37, 0xa001, 0xffff, true, true),

                Crc16Preset.Riello =>
                    new CrcConfig16(16, 0x63d0, 0x8408, 0x554d, true, true),

                Crc16Preset.SpiFujitsu =>
                    new CrcConfig16(16, 0xe5cc, 0x1021, 0x1d0f),

                Crc16Preset.T10Dif =>
                    new CrcConfig16(16, 0xd0db, 0x8bb7),

                Crc16Preset.TeleDisk =>
                    new CrcConfig16(16, 0x0fb3, 0xa097),

                Crc16Preset.Tms37157 =>
                    new CrcConfig16(16, 0x26b1, 0x8408, 0x3791, true, true),

                Crc16Preset.Usb =>
                    new CrcConfig16(16, 0xb4c8, 0xa001, 0xffff, true, true, 0xffff),

                Crc16Preset.XModem =>
                    new CrcConfig16(16, 0x31c3, 0x1021),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-17 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-17 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(Crc17Preset preset) =>
            preset switch
            {
                Crc17Preset.Default =>
                    new CrcConfig32(17, 0x04f03u, 0x1685bu, default, false, false, default, 0x33ffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-21 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-21 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(Crc21Preset preset) =>
            preset switch
            {
                Crc21Preset.Default =>
                    new CrcConfig32(21, 0x0ed841u, 0x102899u, default, false, false, default, 0x1fffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-24 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-24 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(Crc24Preset preset) =>
            preset switch
            {
                Crc24Preset.Default =>
                    new CrcConfig32(24, 0x21cf02u, 0x864cfbu, 0xb704ceu),

                Crc24Preset.Ble =>
                    new CrcConfig32(24, 0xc25a56u, 0xda6000u, 0xaaaaaau, true, true),

                Crc24Preset.LteA =>
                    new CrcConfig32(24, 0xcde703u, 0x864cfbu),

                Crc24Preset.LteB =>
                    new CrcConfig32(24, 0x23ef52u, 0x800063u),

                Crc24Preset.FlexRayA =>
                    new CrcConfig32(24, 0x7979bdu, 0x5d6dcbu, 0xfedcbau),

                Crc24Preset.FlexRayB =>
                    new CrcConfig32(24, 0x1f23b8u, 0x5d6dcbu, 0xabcdefu),

                Crc24Preset.Interlaken =>
                    new CrcConfig32(24, 0xb4f3e6u, 0x328b63u, 0xffffffu, false, false, 0xffffffu),

                Crc24Preset.Os9 =>
                    new CrcConfig32(24, 0x200fa5u, 0x800063u, 0xffffffu, false, false, 0xffffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-30 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-30 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(Crc30Preset preset) =>
            preset switch
            {
                Crc30Preset.Default =>
                    new CrcConfig32(30, 0x04c34abfu, 0x2030b9c7u, 0x3fffffffu, false, false, 0x3fffffffu, 0x3fffffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-31 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-31 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(Crc31Preset preset) =>
            preset switch
            {
                Crc31Preset.Default =>
                    new CrcConfig32(31, 0x0ce9e46cu, 0x4c11db7u, 0x7fffffffu, false, false, 0x7fffffffu, 0x7fffffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-32 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-32 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(Crc32Preset preset) =>
            preset switch
            {
                Crc32Preset.Default =>
                    new CrcConfig32(32, 0xcbf43926u, 0xedb88320u, 0xffffffffu, true, true, 0xffffffffu),

                Crc32Preset.Autosar =>
                    new CrcConfig32(32, 0x1697d06au, 0xc8df352fu, 0xffffffffu, true, true, 0xffffffffu),

                Crc32Preset.CdRomEdc =>
                    new CrcConfig32(32, 0x6ec2edc4u, 0xd8018001u, default, true, true),

                Crc32Preset.Q =>
                    new CrcConfig32(32, 0x3010bf7fu, 0x814141abu),

                Crc32Preset.BZip2 =>
                    new CrcConfig32(32, 0xfc891918u, 0x04c11db7u, 0xffffffffu, false, false, 0xffffffffu),

                Crc32Preset.C =>
                    new CrcConfig32(32, 0xe3069283u, 0x82f63b78u, 0xffffffffu, true, true, 0xffffffffu),

                Crc32Preset.D =>
                    new CrcConfig32(32, 0x87315576u, 0xd419cc15u, 0xffffffffu, true, true, 0xffffffffu),

                Crc32Preset.JamCrc =>
                    new CrcConfig32(32, 0x340bc6d9u, 0xedb88320u, 0xffffffffu, true, true),

                Crc32Preset.Mpeg2 =>
                    new CrcConfig32(32, 0x0376e6e7u, 0x04c11db7u, 0xffffffffu),

                Crc32Preset.Posix =>
                    new CrcConfig32(32, 0x765e7680u, 0x04c11db7u, default, false, false, 0xffffffffu),

                Crc32Preset.Xfer =>
                    new CrcConfig32(32, 0xbd0be338u, 0x000000afu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-40 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-40 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ulong> GetConfig(Crc40Preset preset) =>
            preset switch
            {
                Crc40Preset.Default =>
                    new CrcConfig64(40, 0xd4164fc646uL, 0x0004820009uL, default, false, false, 0xffffffffffuL),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-64 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-64 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ulong> GetConfig(Crc64Preset preset) =>
            preset switch
            {
                Crc64Preset.Default =>
                    new CrcConfig64(64, 0x6c40df5f0b497347uL, 0x42f0e1eba9ea3693uL),

                Crc64Preset.We =>
                    new CrcConfig64(64, 0x62ec59e3f1a4f00auL, 0x42f0e1eba9ea3693uL, 0xffffffffffffffffuL, false, false, 0xffffffffffffffffuL),

                Crc64Preset.Xz =>
                    new CrcConfig64(64, 0x995dc9bbdf1939fauL, 0xc96c5795d7870f42uL, 0xffffffffffffffffuL, true, true, 0xffffffffffffffffuL),

                Crc64Preset.GoIso =>
                    new CrcConfig64(64, 0xb90956c775a41001uL, 0xd800000000000000uL, 0xffffffffffffffffuL, true, true, 0xffffffffffffffffuL),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-82 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-82 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<BigInteger> GetConfig(Crc82Preset preset) =>
            preset switch
            {
                Crc82Preset.Default =>
                    new CrcConfigBeyond(82, "09ea83f625023801fd612".ToBigInt(), "220808a00a2022200c430".ToBigInt(), default, true, true, default, "3ffffffffffffffffffff".ToBigInt()),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
    }
}
