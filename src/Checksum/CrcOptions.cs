namespace Roydl.Crypto.Checksum
{
    /// <summary>Provides enumerated constants that are used to load CRC configurations.</summary>
    public static class CrcOptions
    {
        /// <summary>Specifies which CRC-8 configuration should be loaded.</summary>
        public enum Crc
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

            /// <summary>CRC-8/TECH-3250.
            ///     <para><b>Alias:</b> AES, EBU.</para>
            /// </summary>
            Tech3250,

            /// <summary>CRC-8/WCDMA.</summary>
            /// ReSharper restore CommentTypo
            Wcdma
        }

        /// <summary>Specifies which CRC-10 configuration should be loaded.</summary>
        public enum Crc10
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

        /// <summary>Specifies which CRC-11 configuration should be loaded.</summary>
        public enum Crc11
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

        /// <summary>Specifies which CRC-12 configuration should be loaded.</summary>
        public enum Crc12
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

            /// <summary>CRC-12/GSM.</summary>
            Gsm,

            /// <summary>CRC-12/UMTS.
            ///     <para><b>Alias:</b> 3GPP.</para>
            /// </summary>
            /// ReSharper restore CommentTypo
            Umts
        }

        /// <summary>Specifies which CRC-13 configuration should be loaded.</summary>
        public enum Crc13
        {
            /// <summary>CRC-13.
            ///     <para><b>Alias:</b> BBC.</para>
            /// </summary>
            Default
        }

        /// <summary>Specifies which CRC-14 configuration should be loaded.</summary>
        public enum Crc14
        {
            /// ReSharper disable once CommentTypo
            /// <summary>CRC-14.
            ///     <para><b>Alias:</b> DARC.</para>
            /// </summary>
            Default,

            /// <summary>CRC-14/GSM.</summary>
            Gsm
        }

        /// <summary>Specifies which CRC-15 configuration should be loaded.</summary>
        public enum Crc15
        {
            /// <summary>CRC-15.
            ///     <para><b>Alias:</b> CAN.</para>
            /// </summary>
            Default,

            /// <summary>CRC-15/MPT1327.</summary>
            Mpt1327
        }

        /// <summary>Specifies which CRC-16 configuration should be loaded.</summary>
        public enum Crc16
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

        /// <summary>Specifies which CRC-17 configuration should be loaded.</summary>
        public enum Crc17
        {
            /// <summary>CRC-17.
            ///     <para><b>Alias:</b> CAN-FD.</para>
            /// </summary>
            Default
        }

        /// <summary>Specifies which CRC-21 configuration should be loaded.</summary>
        public enum Crc21
        {
            /// <summary>CRC-21.
            ///     <para><b>Alias:</b> CAN-FD.</para>
            /// </summary>
            Default
        }

        /// <summary>Specifies which CRC-24 configuration should be loaded.</summary>
        public enum Crc24
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

        /// <summary>Specifies which CRC-30 configuration should be loaded.</summary>
        public enum Crc30
        {
            /// ReSharper disable once CommentTypo
            /// <summary>CRC-30.
            ///     <para><b>Alias:</b> CDMA.</para>
            /// </summary>
            Default
        }

        /// <summary>Specifies which CRC-31 configuration should be loaded.</summary>
        public enum Crc31
        {
            /// <summary>CRC-31.
            ///     <para><b>Alias:</b> PHILIPS.</para>
            /// </summary>
            Default
        }

        /// <summary>Specifies which CRC-32 configuration should be loaded.</summary>
        public enum Crc32
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

        /// <summary>Specifies which CRC-40 configuration should be loaded.</summary>
        public enum Crc40
        {
            /// <summary>CRC-40.
            ///     <para><b>Alias:</b> GSM.</para>
            /// </summary>
            Default
        }

        /// <summary>Specifies which CRC-64 configuration should be loaded.</summary>
        public enum Crc64
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

        /// <summary>Specifies which CRC-82 configuration should be loaded.</summary>
        public enum Crc82
        {
            /// ReSharper disable once CommentTypo
            /// <summary>CRC-82.
            ///     <para><b>Alias:</b> DARC.</para>
            /// </summary>
            Default
        }
    }
}
