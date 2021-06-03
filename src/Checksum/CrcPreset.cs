namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Numerics;
    using Internal;

    /// <summary>Specifies enumerated constants used to define an CRC-8 preset.</summary>
    public enum Crc08Preset
    {
        /// ReSharper disable CommentTypo
        /// <summary>CRC-8.
        ///     <para><b>Alias:</b> SMBUS.</para>
        /// </summary>
        Default,

        /// <summary>CRC-8/AUTOSAR.</summary>
        Autosar,

        /// <summary>CRC-8/BLUETOOTH.</summary>
        Bluetooth,

        /// <summary>CRC-8/CDMA2000.</summary>
        Cdma2000,

        /// <summary>CRC-8/DARC.</summary>
        Darc,

        /// <summary>CRC-8/DVB-S2.</summary>
        DvbS2,

        /// <summary>CRC-8/GSM-A.</summary>
        GsmA,

        /// <summary>CRC-8/GSM-B.</summary>
        GsmB,

        /// <summary>CRC-8/I-432-1.
        ///     <para><b>Alias:</b> ITU.</para>
        /// </summary>
        I4321,

        /// ReSharper disable once InconsistentNaming
        /// <summary>CRC-8/I-CODE.</summary>
        ICode,

        /// <summary>CRC-8/LTE.</summary>
        Lte,

        /// <summary>CRC-8/MAXIM.
        ///     <para><b>Alias:</b> MAXIM-DOW, DOW-CRC.</para>
        /// </summary>
        Maxim,

        /// <summary>CRC-8/MIFARE-MAD.</summary>
        MifareMad,

        /// <summary>CRC-8/NRSC-5.</summary>
        Nrsc5,

        /// <summary>CRC-8/OPENSAFETY.</summary>
        OpenSafety,

        /// <summary>CRC-8/ROHC.</summary>
        Rohc,

        /// <summary>CRC-8/SAE-J1850.</summary>
        SaeJ1850,

        /// <summary>CRC-8/TECH-3250.</summary>
        Tech3250,

        /// <summary>CRC-8/WCDMA.</summary>
        /// ReSharper restore CommentTypo
        Wcdma
    }

    /// <summary>Specifies enumerated constants used to define an CRC-10 preset.</summary>
    public enum Crc10Preset
    {
        /// <summary>CRC-10.
        ///     <para><b>Alias:</b> ATM, I-610.</para>
        /// </summary>
        Default,

        /// ReSharper disable once CommentTypo
        /// <summary>CRC-10/CDMA2000.</summary>
        Cdma2000,

        /// <summary>CRC-10/GSM.</summary>
        Gsm
    }

    /// <summary>Specifies enumerated constants used to define an CRC-11 preset.</summary>
    public enum Crc11Preset
    {
        /// ReSharper disable CommentTypo
        /// <summary>CRC-11.
        ///     <para><b>Alias:</b> FLEXRAY.</para>
        /// </summary>
        Default,

        /// <summary>CRC-11/UMTS.</summary>
        /// ReSharper restore CommentTypo
        Umts
    }

    /// <summary>Specifies enumerated constants used to define an CRC-12 preset.</summary>
    public enum Crc12Preset
    {
        /// ReSharper disable CommentTypo
        /// <summary>CRC-12.
        ///     <para><b>Alias:</b> CDMA2000.</para>
        /// </summary>
        Default,

        /// <summary>CRC-12/DECT.
        ///     <para><b>Alias:</b> X-CRC-12.</para>
        /// </summary>
        Dect,

        /// <summary>CRC-12/GSM.
        ///     <para><b>Alias:</b> DECT.</para>
        /// </summary>
        Gsm,

        /// <summary>CRC-12/UMTS.
        ///     <para><b>Alias:</b> 3GPP.</para>
        /// </summary>
        /// ReSharper restore CommentTypo
        Umts
    }

    /// <summary>Specifies enumerated constants used to define an CRC-13 preset.</summary>
    public enum Crc13Preset
    {
        /// <summary>CRC-13.
        ///     <para><b>Alias:</b> BBC.</para>
        /// </summary>
        Default
    }

    /// <summary>Specifies enumerated constants used to define an CRC-14 preset.</summary>
    public enum Crc14Preset
    {
        /// ReSharper disable once CommentTypo
        /// <summary>CRC-14.
        ///     <para><b>Alias:</b> DARC.</para>
        /// </summary>
        Default,

        /// <summary>CRC-14/GSM.</summary>
        Gsm
    }

    /// <summary>Specifies enumerated constants used to define an CRC-15 preset.</summary>
    public enum Crc15Preset
    {
        /// <summary>CRC-15.
        ///     <para><b>Alias:</b> CAN.</para>
        /// </summary>
        Default,

        /// <summary>CRC-15/MPT1327.</summary>
        Mpt1327
    }

    /// <summary>Specifies enumerated constants used to define an CRC-16 preset.</summary>
    public enum Crc16Preset
    {
        /// <summary>CRC-16.
        ///     <para><b>Alias:</b> ARC, IBM, LHA.</para>
        /// </summary>
        Default,

        /// <summary>CRC-16/A.</summary>
        A,

        /// ReSharper disable CommentTypo
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
        /// ReSharper restore CommentTypo
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
        /// ReSharper disable CommentTypo
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
        /// ReSharper restore CommentTypo
        Interlaken,

        /// <summary>CRC-24/OS-9.</summary>
        Os9
    }

    /// <summary>Specifies enumerated constants used to define an CRC-30 preset.</summary>
    public enum Crc30Preset
    {
        /// ReSharper disable once CommentTypo
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
        /// ReSharper disable CommentTypo
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
        /// ReSharper restore CommentTypo
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
        /// ReSharper disable once CommentTypo
        /// <summary>CRC-82.
        ///     <para><b>Alias:</b> DARC.</para>
        /// </summary>
        Default
    }

    /// <summary>Provides static functions for loading preset <see cref="ICrcConfig{TValue}"/> structures.</summary>
    public static class CrcPreset
    {
        /// <summary>Loads a predefined CRC-8 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-8 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<byte> GetConfig(Crc08Preset preset) =>
            preset switch
            {
                Crc08Preset.Default =>
                    new CrcConfig(8, 0xf4, 0x07),

                Crc08Preset.Autosar =>
                    new CrcConfig(8, 0xdf, 0x2f, 0xff, false, false, 0xff),

                Crc08Preset.Bluetooth =>
                    new CrcConfig(8, 0x26, 0xe5, default, true, true),

                Crc08Preset.Cdma2000 =>
                    new CrcConfig(8, 0xda, 0x9b, 0xff),

                Crc08Preset.Darc =>
                    new CrcConfig(8, 0x15, 0b_10011100, default, true, true),

                Crc08Preset.DvbS2 =>
                    new CrcConfig(8, 0xbc, 0xd5),

                Crc08Preset.GsmA =>
                    new CrcConfig(8, 0x37, 0x1d),

                Crc08Preset.GsmB =>
                    new CrcConfig(8, 0x94, 0x49, default, false, false, 0xff),

                Crc08Preset.I4321 =>
                    new CrcConfig(8, 0xa1, 0x07, default, false, false, 0x55),

                Crc08Preset.ICode =>
                    new CrcConfig(8, 0x7e, 0x1d, 0xfd),

                Crc08Preset.Lte =>
                    new CrcConfig(8, 0xea, 0x9b),

                Crc08Preset.Maxim =>
                    new CrcConfig(8, 0xa1, 0x8c, default, true, true),

                Crc08Preset.MifareMad =>
                    new CrcConfig(8, 0x99, 0x1d, 0xc7),

                Crc08Preset.Nrsc5 =>
                    new CrcConfig(8, 0xf7, 0x31, 0xff),

                Crc08Preset.OpenSafety =>
                    new CrcConfig(8, 0x3e, 0x2f),

                Crc08Preset.Rohc =>
                    new CrcConfig(8, 0xd0, 0xe0, 0xff, true, true),

                Crc08Preset.SaeJ1850 =>
                    new CrcConfig(8, 0x4b, 0x1d, 0xff, false, false, 0xff),

                Crc08Preset.Tech3250 =>
                    new CrcConfig(8, 0x97, 0xb8, 0xff, true, true),

                Crc08Preset.Wcdma =>
                    new CrcConfig(8, 0x25, 0xd9, default, true, true),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-10 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-10 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(Crc10Preset preset) =>
            preset switch
            {
                Crc10Preset.Default =>
                    new CrcConfig16(10, 0x199, 0x233, default, false, false, default, 0x3ff),

                Crc10Preset.Cdma2000 =>
                    new CrcConfig16(10, 0x233, 0x3d9, 0x3ff, false, false, default, 0x3ff),

                Crc10Preset.Gsm =>
                    new CrcConfig16(10, 0x12a, 0x175, default, false, false, 0x3ff, 0x3ff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-11 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-11 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(Crc11Preset preset) =>
            preset switch
            {
                Crc11Preset.Default =>
                    new CrcConfig16(11, 0x5a3, 0x385, 0x01a),

                Crc11Preset.Umts =>
                    new CrcConfig16(11, 0x061, 0x307, default, false, false, default, 0x7ff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-12 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-12 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(Crc12Preset preset) =>
            preset switch
            {
                Crc12Preset.Default =>
                    new CrcConfig16(12, 0xd4d, 0xf13, 0xfff, false, false, default, 0xfff),

                Crc12Preset.Dect =>
                    new CrcConfig16(12, 0xf5b, 0x80f, default, false, false, default, 0xfff),

                Crc12Preset.Gsm =>
                    new CrcConfig16(12, 0xb34, 0xd31, default, false, false, 0xfff, 0xfff),

                Crc12Preset.Umts =>
                    new CrcConfig16(12, 0xdaf, 0x80f, default, false, true, default, 0xfff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-13 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-13 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(Crc13Preset preset) =>
            preset switch
            {
                Crc13Preset.Default =>
                    new CrcConfig16(13, 0x04fa, 0x1cf5, default, false, false, default, 0x1fff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-14 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-14 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(Crc14Preset preset) =>
            preset switch
            {
                Crc14Preset.Default =>
                    new CrcConfig16(14, 0x082d, 0x2804, default, true, true, default, 0x3fff),

                Crc14Preset.Gsm =>
                    new CrcConfig16(14, 0x30ae, 0x202d, default, false, false, 0x3fff, 0x3fff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

        /// <summary>Loads a predefined CRC-15 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-15 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(Crc15Preset preset) =>
            preset switch
            {
                Crc15Preset.Default =>
                    new CrcConfig16(15, 0x059e, 0x4599),

                Crc15Preset.Mpt1327 =>
                    new CrcConfig16(15, 0x2566, 0x6815, default, false, false, 0x0001, 0x7fff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };

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
