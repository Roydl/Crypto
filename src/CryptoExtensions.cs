namespace Roydl.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Linq;
    using System.Numerics;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Text.Json;
    using Checksum;

    /// <summary>Specifies enumerated constants used to define an algorithm for encrypting data.</summary>
    public enum ChecksumAlgo
    {
        /// ReSharper disable CommentTypo
        /// <summary>Adler-32.</summary>
        Adler32,

        /// <summary>CRC-8.
        ///     <para><b>Alias:</b> SMBUS.</para>
        /// </summary>
        Crc08,

        /// <summary>CRC-8/AUTOSAR.</summary>
        Crc08Autosar,

        /// <summary>CRC-8/BLUETOOTH.</summary>
        Crc08Bluetooth,

        /// <summary>CRC-8/CDMA2000.</summary>
        Crc08Cdma2000,

        /// <summary>CRC-8/DARC.</summary>
        Crc08Darc,

        /// <summary>CRC-8/DVB-S2.</summary>
        Crc08DvbS2,

        /// <summary>CRC-8/GSM-A.</summary>
        Crc08GsmA,

        /// <summary>CRC-8/GSM-B.</summary>
        Crc08GsmB,

        /// <summary>CRC-8/I-432-1.
        ///     <para><b>Alias:</b> ITU.</para>
        /// </summary>
        Crc08I4321,

        /// <summary>CRC-8/I-CODE.</summary>
        Crc08ICode,

        /// <summary>CRC-8/LTE.</summary>
        Crc08Lte,

        /// <summary>CRC-8/MAXIM.
        ///     <para><b>Alias:</b> MAXIM-DOW, DOW-CRC.</para>
        /// </summary>
        Crc08Maxim,

        /// <summary>CRC-8/MIFARE-MAD.</summary>
        Crc08MifareMad,

        /// <summary>CRC-8/NRSC-5.</summary>
        Crc08Nrsc5,

        /// <summary>CRC-8/OPENSAFETY.</summary>
        Crc08OpenSafety,

        /// <summary>CRC-8/ROHC.</summary>
        Crc08Rohc,

        /// <summary>CRC-8/SAE-J1850.</summary>
        Crc08SaeJ1850,

        /// <summary>CRC-8/TECH-3250.
        ///     <para><b>Alias:</b> AES, EBU.</para>
        /// </summary>
        Crc08Tech3250,

        /// <summary>CRC-8/WCDMA.</summary>
        Crc08Wcdma,

        /// <summary>CRC-10.
        ///     <para><b>Alias:</b> ATM, I-610.</para>
        /// </summary>
        Crc10,

        /// <summary>CRC-10/CDMA2000.</summary>
        Crc10Cdma2000,

        /// <summary>CRC-10/GSM.</summary>
        Crc10Gsm,

        /// <summary>CRC-11.
        ///     <para><b>Alias:</b> FLEXRAY.</para>
        /// </summary>
        Crc11,

        /// <summary>CRC-11/UMTS.</summary>
        Crc11Umts,

        /// <summary>CRC-12.
        ///     <para><b>Alias:</b> CDMA2000.</para>
        /// </summary>
        Crc12,

        /// <summary>CRC-12/DECT.
        ///     <para><b>Alias:</b> X-CRC-12.</para>
        /// </summary>
        Crc12Dect,

        /// <summary>CRC-12/GSM.
        ///     <para><b>Alias:</b> DECT.</para>
        /// </summary>
        Crc12Gsm,

        /// <summary>CRC-12/UMTS.
        ///     <para><b>Alias:</b> 3GPP.</para>
        /// </summary>
        Crc12Umts,

        /// <summary>CRC-13.
        ///     <para><b>Alias:</b> BBC.</para>
        /// </summary>
        Crc13,

        /// <summary>CRC-14.
        ///     <para><b>Alias:</b> DARC.</para>
        /// </summary>
        Crc14,

        /// <summary>CRC-14/GSM.</summary>
        Crc14Gsm,

        /// <summary>CRC-15.
        ///     <para><b>Alias:</b> CAN.</para>
        /// </summary>
        Crc15,

        /// <summary>CRC-15/MPT1327.</summary>
        Crc15Mpt1327,

        /// <summary>CRC-16.
        ///     <para><b>Alias:</b> ARC, IBM, LHA.</para>
        /// </summary>
        Crc16,

        /// <summary>CRC-16/A.</summary>
        Crc16A,

        /// <summary>CRC-16/BUYPASS.</summary>
        Crc16Buypass,

        /// <summary>CRC-16/CDMA2000.</summary>
        Crc16Cdma2000,

        /// <summary>CRC-16/CMS.</summary>
        Crc16Cms,

        /// <summary>CRC-16/DDS-110.</summary>
        Crc16Dds110,

        /// <summary>CRC-16/DECT-R.
        ///     <para><b>Alias:</b> R-CRC-16</para>
        /// </summary>
        Crc16DectR,

        /// <summary>CRC-16/DECT-X.
        ///     <para><b>Alias:</b> X-CRC-16</para>
        /// </summary>
        Crc16DectX,

        /// <summary>CRC-16/DNP.</summary>
        Crc16Dnp,

        /// <summary>CRC-16/EN-13757.</summary>
        Crc16En13757,

        /// <summary>CRC-16/GENIBUS.
        ///     <para><b>Alias:</b> DARC, EPC, EPC-C1G2, I-CODE</para>
        /// </summary>
        Crc16Genibus,

        /// <summary>CRC-16/GSM.</summary>
        Crc16Gsm,

        /// <summary>CRC-16/IBM-3740.
        ///     <para><b>Alias:</b> AUTOSAR, CCITT-FALSE</para>
        /// </summary>
        Crc16Ibm3740,

        /// <summary>CRC-16/IBM-SDLC.
        ///     <para><b>Alias:</b> ISO-HDLC, ISO-IEC-14443-3-B, CRC-B, X-25</para>
        /// </summary>
        Crc16IbmSdlc,

        /// <summary>CRC-16/KERMIT.</summary>
        Crc16Kermit,

        /// <summary>CRC-16/LJ1200.</summary>
        Crc16Lj1200,

        /// <summary>CRC-16/MAXIM.</summary>
        /// <para><b>Alias:</b> MAXIM-DOW</para>
        Crc16Maxim,

        /// <summary>CRC-16/MCRF4XX.</summary>
        Crc16Mcrf4Xx,

        /// <summary>CRC-16/MODBUS.</summary>
        Crc16ModBus,

        /// <summary>CRC-16/RIELLO.</summary>
        Crc16Riello,

        /// <summary>CRC-16/SPI-FUJITSU.
        ///     <para><b>Alias:</b> AUG-CCITT</para>
        /// </summary>
        Crc16SpiFujitsu,

        /// <summary>CRC-16/T10-DIF.</summary>
        Crc16T10Dif,

        /// <summary>CRC-16/TELEDISK.</summary>
        Crc16TeleDisk,

        /// <summary>CRC-16/TMS37157.</summary>
        Crc16Tms37157,

        /// <summary>CRC-16/USB.</summary>
        Crc16Usb,

        /// <summary>CRC-16/XMODEM.</summary>
        Crc16XModem,

        /// <summary>CRC-17.
        ///     <para><b>Alias:</b> CAN-FD.</para>
        /// </summary>
        Crc17,

        /// <summary>CRC-21.
        ///     <para><b>Alias:</b> CAN-FD.</para>
        /// </summary>
        Crc21,

        /// <summary>CRC-24.
        ///     <para><b>Alias:</b> OPENPGP.</para>
        /// </summary>
        Crc24,

        /// <summary>CRC-24/BLE.</summary>
        Crc24Ble,

        /// <summary>CRC-24/LTE-A.</summary>
        Crc24LteA,

        /// <summary>CRC-24/LTE-B.</summary>
        Crc24LteB,

        /// <summary>CRC-24/FLEXRAY-A.</summary>
        Crc24FlexRayA,

        /// <summary>CRC-24/FLEXRAY-B.</summary>
        Crc24FlexRayB,

        /// <summary>CRC-24/INTERLAKEN.</summary>
        Crc24Interlaken,

        /// <summary>CRC-24/OS-9.</summary>
        Crc24Os9,

        /// <summary>CRC-30.
        ///     <para><b>Alias:</b> CDMA.</para>
        /// </summary>
        Crc30,

        /// <summary>CRC-31.
        ///     <para><b>Alias:</b> PHILIPS.</para>
        /// </summary>
        Crc31,

        /// <summary>CRC-32/ISO-HDLC.
        ///     <para><b>Alias:</b> ADCCP, ISO-HDLC, PKZip, V-24, XZ.</para>
        /// </summary>
        Crc32,

        /// <summary>CRC-32/AUTOSAR.</summary>
        Crc32Autosar,

        /// <summary>CRC-32/CD-ROM-EDC.</summary>
        Crc32CdRomEdc,

        /// <summary>CRC-32/Q.
        ///     <para><b>Alias:</b> AIXM.</para>
        /// </summary>
        Crc32Q,

        /// <summary>CRC-32/BZIP2.
        ///     <para><b>Alias:</b> AAL5, DECT-B, B-CRC.</para>
        /// </summary>
        Crc32BZip2,

        /// <summary>CRC-32/C.
        ///     <para><b>Alias:</b> BASE91-C, Castagnoli, Interlaken, ISCSI.</para>
        /// </summary>
        Crc32C,

        /// <summary>CRC-32/D.
        ///     <para><b>Alias:</b> BASE91-D.</para>
        /// </summary>
        Crc32D,

        /// <summary>CRC-32/JAMCRC.</summary>
        Crc32JamCrc,

        /// <summary>CRC-32/MPEG-2.</summary>
        Crc32Mpeg2,

        /// <summary>CRC-32/POSIX.
        ///     <para><b>Alias:</b> CKSUM.</para>
        /// </summary>
        Crc32Posix,

        /// <summary>CRC-32/XFER.</summary>
        Crc32Xfer,

        /// <summary>CRC-40.
        ///     <para><b>Alias:</b> GSM.</para>
        /// </summary>
        Crc40,

        /// <summary>CRC-64.
        ///     <para><b>Alias:</b> ECMA-182.</para>
        /// </summary>
        Crc64,

        /// <summary>CRC-64/WE.</summary>
        Crc64We,

        /// <summary>CRC-64/XZ.
        ///     <para><b>Alias:</b> GO-ECMA.</para>
        /// </summary>
        Crc64Xz,

        /// <summary>CRC-64/GO-ISO.</summary>
        Crc64GoIso,

        /// <summary>CRC-82.
        ///     <para><b>Alias:</b> DARC.</para>
        /// </summary>
        Crc82,

        /// <summary>MD5, 128-bit.</summary>
        Md5,

        /// <summary>SHA-1, 160-bit.</summary>
        Sha1,

        /// <summary>SHA-2, 256-bit.</summary>
        Sha256,

        /// <summary>SHA-2, 384-bit.</summary>
        Sha384,

        /// <summary>SHA-2, 512-bit.</summary>
        /// ReSharper restore CommentTypo
        Sha512
    }

    /// <summary>Provides extension methods for data encryption and decryption.</summary>
    public static class CryptoExtensions
    {
        /// <summary>Encrypts this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns the 64-bit unsigned integer representation of the computed hash code.</summary>
        /// <exception cref="ArgumentNullException">source is null.</exception>
        /// <exception cref="ArgumentException">source is empty.</exception>
        /// <exception cref="FileNotFoundException">source cannot be found.</exception>
        /// <exception cref="UnauthorizedAccessException">source is a directory.</exception>
        /// <exception cref="IOException">source is already open, or an I/O error occurs.</exception>
        /// <exception cref="NotSupportedException">source does not support reading.</exception>
        /// <returns>A 64-bit unsigned integer that contains the result of encrypting the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>.</returns>
        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static ulong GetCipher<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256) =>
            InternalGenericEncrypt(source, algorithm, false) switch
            {
                IChecksumResult<byte> x => x.HashNumber,
                IChecksumResult<ushort> x => x.HashNumber,
                IChecksumResult<uint> x => x.HashNumber,
                IChecksumResult<ulong> x => x.HashNumber,
                IChecksumResult<BigInteger> x => (ulong)(x.HashNumber & ulong.MaxValue),
                _ => default
            };

        /// <summary>Encrypts this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns the string representation of the computed hash code.</summary>
        /// <returns>A string that contains the result of encrypting the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>.</returns>
        /// <inheritdoc cref="GetCipher{TSource}(TSource, ChecksumAlgo)"/>
        [return: NotNullIfNotNull("source")]
        public static string GetChecksum<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256) =>
            InternalGenericEncrypt(source, algorithm, false).Hash;

        /// <summary>Encrypts the file at this <paramref name="path"/> with the specified <paramref name="algorithm"/> and returns the string representation of the computed hash code.</summary>
        /// <param name="path">The full path of the file to encrypt.</param>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <returns>A string that contains the result of encrypting the file at specified <paramref name="path"/> by the specified <paramref name="algorithm"/>.</returns>
        /// <inheritdoc cref="IChecksumAlgorithm.EncryptFile(string)"/>
        public static string GetFileChecksum(this string path, ChecksumAlgo algorithm = ChecksumAlgo.Sha256)
        {
            var instance = algorithm.GetDefaultInstance();
            instance.EncryptFile(path);
            return instance.Hash;
        }

        /// <summary>Encrypts this <paramref name="source"/> object with the specified <paramref name="algorithm1"/> and the specified <paramref name="algorithm2"/> and combines the bytes of both hashes into a unique GUID string.</summary>
        /// <param name="source">The object to encrypt.</param>
        /// <param name="braces"><see langword="true"/> to place the GUID between braces; otherwise, <see langword="false"/>.</param>
        /// <param name="algorithm1">The first algorithm to use.</param>
        /// <param name="algorithm2">The second algorithm to use.</param>
        /// <returns>A string with a GUID that contains the results of encrypting the specified <paramref name="source"/> object by the specified <paramref name="algorithm1"/> and the specified <paramref name="algorithm2"/>.</returns>
        /// <inheritdoc cref="GetCipher{TSource}(TSource, ChecksumAlgo)"/>
        [return: NotNullIfNotNull("source")]
        public static string GetGuid<TSource>(this TSource source, bool braces = false, ChecksumAlgo algorithm1 = ChecksumAlgo.Crc32, ChecksumAlgo algorithm2 = ChecksumAlgo.Sha256)
        {
            var sb = new StringBuilder(braces ? 38 : 36);
            if (braces)
                sb.Append('{');
            var raw1 = InternalGenericEncrypt(source, algorithm1, true).RawHash.Span;
            var raw2 = InternalGenericEncrypt(source, algorithm2, false).RawHash.Span;
            var span = LocalCombineHashBytes(raw1, raw2, 16);
            var index = 0;
            for (var i = 0; i < 5; i++)
            {
                var size = i switch { < 1 => 4, < 4 => 2, _ => 6 };
                for (var j = 0; j < size; j++)
                    sb.AppendFormat("{0:x2}", span[index++]);
                if (i < 4)
                    sb.Append('-');
            }
            if (braces)
                sb.Append('}');
            var str = sb.ToString();
            sb.Clear();
            return str;

            static Span<byte> LocalCombineHashBytes(ReadOnlySpan<byte> span1, ReadOnlySpan<byte> span2, int size)
            {
                var ba = new byte[size].AsSpan();
                var i1 = 0;
                var i2 = 0;
                for (var i = 0; i < size; i++)
                {
                    var e1 = span1.IsEmpty ? byte.MinValue : span1[i1 < span1.Length ? i1++ : i1 = 0];
                    var e2 = span2.IsEmpty ? byte.MaxValue : span2[i2 < span2.Length ? i2++ : i2 = 0];
                    ba[i] = (byte)CryptoUtils.CombineHashCodes(e1, e2);
                }
                return ba;
            }
        }

#if NET5_0_OR_GREATER
        /// <summary>Tries to encrypt this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns a <see cref="bool"/> value that determines whether the encryption was successful. All possible exceptions are caught.</summary>
        /// <typeparam name="TSource">The type of source.</typeparam>
        /// <param name="source">The object to encrypt.</param>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <param name="hash">If successful, the result of encrypting the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>; otherwise, <see langword="default"/>.</param>
        /// <remarks>
        ///     <list type="table">
        ///         <item><term>Known</term>&#160;<description><see cref="bool"/>, <see cref="sbyte"/>, <see cref="byte"/>, <see cref="short"/>, <see cref="ushort"/>, <see cref="char"/>, <see cref="int"/>, <see cref="uint"/>, <see cref="long"/>, <see cref="ulong"/>, <see cref="Half"/>, <see cref="float"/>, <see cref="double"/>, <see cref="decimal"/>, <see cref="Enum"/>, <see cref="IntPtr"/>, <see cref="UIntPtr"/>, <see cref="Vector{T}"/>, <see cref="Vector2"/>, <see cref="Vector3"/>, <see cref="Vector4"/>, <see cref="Matrix3x2"/>, <see cref="Matrix4x4"/>, <see cref="Plane"/>, <see cref="Quaternion"/>, <see cref="Complex"/>, <see cref="BigInteger"/>, <see cref="DateTime"/>, <see cref="DateTimeOffset"/>, <see cref="TimeSpan"/>, <see cref="Guid"/>, <see cref="Rune"/>, <see cref="Stream"/>, <see cref="StreamReader"/>, <see cref="FileInfo"/>, any <see cref="IEnumerable{T}"/> <see cref="byte"/> sequence, i.e. <see cref="Array"/>, or any <see cref="IEnumerable{T}"/> <see cref="char"/> sequence, i.e. <see cref="string"/>.</description></item>
        ///         <item><term>Otherwise</term>&#160;<description>An attempt is made to convert <paramref name="source"/> to a byte array for the encryption, which should work for all <see href="https://docs.microsoft.com/en-us/dotnet/framework/interop/blittable-and-non-blittable-types">blittable types</see>. If this fails, <paramref name="source"/> is serialized using <see cref="Utf8JsonWriter"/> and the result is encrypted.</description></item>
        ///     </list>
        /// </remarks>
        /// <returns><see langword="true"/> if the specified <paramref name="source"/> could be encrypted by the specified <paramref name="algorithm"/>; otherwise, <see langword="false"/>.</returns>
#else
        /// <summary>Tries to encrypt this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns a <see cref="bool"/> value that determines whether the encryption was successful. All possible exceptions are caught.</summary>
        /// <typeparam name="TSource">The type of source.</typeparam>
        /// <param name="source">The object to encrypt.</param>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <param name="hash">If successful, the result of encrypting the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>; otherwise, <see langword="default"/>.</param>
        /// <remarks>
        ///     <list type="table">
        ///         <item><term>Known</term>&#160;<description><see cref="bool"/>, <see cref="sbyte"/>, <see cref="byte"/>, <see cref="short"/>, <see cref="ushort"/>, <see cref="char"/>, <see cref="int"/>, <see cref="uint"/>, <see cref="long"/>, <see cref="ulong"/>, <see cref="float"/>, <see cref="double"/>, <see cref="decimal"/>, <see cref="Enum"/>, <see cref="IntPtr"/>, <see cref="UIntPtr"/>, <see cref="Vector{T}"/>, <see cref="Vector2"/>, <see cref="Vector3"/>, <see cref="Vector4"/>, <see cref="Matrix3x2"/>, <see cref="Matrix4x4"/>, <see cref="Plane"/>, <see cref="Quaternion"/>, <see cref="Complex"/>, <see cref="BigInteger"/>, <see cref="DateTime"/>, <see cref="DateTimeOffset"/>, <see cref="TimeSpan"/>, <see cref="Guid"/>, <see cref="Rune"/>, <see cref="Stream"/>, <see cref="StreamReader"/>, <see cref="FileInfo"/>, any <see cref="IEnumerable{T}"/> <see cref="byte"/> sequence, i.e. <see cref="Array"/>, or any <see cref="IEnumerable{T}"/> <see cref="char"/> sequence, i.e. <see cref="string"/>.</description></item>
        ///         <item><term>Otherwise</term>&#160;<description>An attempt is made to convert <paramref name="source"/> to a byte array for the encryption, which should work for all <see href="https://docs.microsoft.com/en-us/dotnet/framework/interop/blittable-and-non-blittable-types">blittable types</see>. If this fails, <paramref name="source"/> is serialized using <see cref="Utf8JsonWriter"/> and the result is encrypted.</description></item>
        ///     </list>
        /// </remarks>
        /// <returns><see langword="true"/> if the specified <paramref name="source"/> could be encrypted by the specified <paramref name="algorithm"/>; otherwise, <see langword="false"/>.</returns>
#endif
        public static bool TryGetCipher<TSource>(this TSource source, ChecksumAlgo algorithm, out ulong hash)
        {
            try
            {
                hash = source.GetCipher(algorithm);
                return hash > 0;
            }
            catch
            {
                hash = default;
                return false;
            }
        }

        /// <summary>Encrypts this <paramref name="source"/> object with the <see cref="ChecksumAlgo.Sha256"/> algorithm and returns a <see cref="bool"/> value that determines whether the encryption was successful. All possible exceptions are caught.</summary>
        /// <typeparam name="TSource">The type of source.</typeparam>
        /// <param name="source">The object to encrypt.</param>
        /// <param name="hash">If successful, the result of encrypting the specified <paramref name="source"/> object by the <see cref="ChecksumAlgo.Sha256"/> algorithm; otherwise, <see langword="default"/>.</param>
        /// <returns><see langword="true"/> if the specified <paramref name="source"/> could be encrypted by the <see cref="ChecksumAlgo.Sha256"/> algorithm; otherwise, <see langword="false"/>.</returns>
        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static bool TryGetCipher<TSource>(this TSource source, out ulong hash) =>
            source.TryGetCipher(ChecksumAlgo.Sha256, out hash);

        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static bool TryGetChecksum<TSource>([NotNullWhen(true)] this TSource source, ChecksumAlgo algorithm, out string hash)
        {
            try
            {
                hash = source.GetChecksum(algorithm);
                return !string.IsNullOrEmpty(hash);
            }
            catch
            {
                hash = default;
                return false;
            }
        }

        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, out ulong)"/>
        public static bool TryGetChecksum<TSource>([NotNullWhen(true)] this TSource source, out string hash) =>
            source.TryGetChecksum(ChecksumAlgo.Sha256, out hash);

        /// <summary>Creates a default instance of this algorithm.</summary>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <returns>A default instance of the specified algorithm.</returns>
        public static IChecksumAlgorithm GetDefaultInstance(this ChecksumAlgo algorithm) =>
            algorithm switch
            {
                ChecksumAlgo.Adler32 => new Adler32(),
                ChecksumAlgo.Crc08 => new Crc<byte>(Crc08Preset.Default),
                ChecksumAlgo.Crc08Autosar => new Crc<byte>(Crc08Preset.Autosar),
                ChecksumAlgo.Crc08Bluetooth => new Crc<byte>(Crc08Preset.Bluetooth),
                ChecksumAlgo.Crc08Cdma2000 => new Crc<byte>(Crc08Preset.Cdma2000),
                ChecksumAlgo.Crc08Darc => new Crc<byte>(Crc08Preset.Darc),
                ChecksumAlgo.Crc08DvbS2 => new Crc<byte>(Crc08Preset.DvbS2),
                ChecksumAlgo.Crc08GsmA => new Crc<byte>(Crc08Preset.GsmA),
                ChecksumAlgo.Crc08GsmB => new Crc<byte>(Crc08Preset.GsmB),
                ChecksumAlgo.Crc08I4321 => new Crc<byte>(Crc08Preset.I4321),
                ChecksumAlgo.Crc08ICode => new Crc<byte>(Crc08Preset.ICode),
                ChecksumAlgo.Crc08Lte => new Crc<byte>(Crc08Preset.Lte),
                ChecksumAlgo.Crc08Maxim => new Crc<byte>(Crc08Preset.Maxim),
                ChecksumAlgo.Crc08MifareMad => new Crc<byte>(Crc08Preset.MifareMad),
                ChecksumAlgo.Crc08Nrsc5 => new Crc<byte>(Crc08Preset.Nrsc5),
                ChecksumAlgo.Crc08OpenSafety => new Crc<byte>(Crc08Preset.OpenSafety),
                ChecksumAlgo.Crc08Rohc => new Crc<byte>(Crc08Preset.Rohc),
                ChecksumAlgo.Crc08SaeJ1850 => new Crc<byte>(Crc08Preset.SaeJ1850),
                ChecksumAlgo.Crc08Tech3250 => new Crc<byte>(Crc08Preset.Tech3250),
                ChecksumAlgo.Crc08Wcdma => new Crc<byte>(Crc08Preset.Wcdma),
                ChecksumAlgo.Crc10 => new Crc<ushort>(Crc10Preset.Default),
                ChecksumAlgo.Crc10Cdma2000 => new Crc<ushort>(Crc10Preset.Cdma2000),
                ChecksumAlgo.Crc10Gsm => new Crc<ushort>(Crc10Preset.Gsm),
                ChecksumAlgo.Crc11 => new Crc<ushort>(Crc11Preset.Default),
                ChecksumAlgo.Crc11Umts => new Crc<ushort>(Crc11Preset.Umts),
                ChecksumAlgo.Crc12 => new Crc<ushort>(Crc12Preset.Default),
                ChecksumAlgo.Crc12Dect => new Crc<ushort>(Crc12Preset.Dect),
                ChecksumAlgo.Crc12Gsm => new Crc<ushort>(Crc12Preset.Gsm),
                ChecksumAlgo.Crc12Umts => new Crc<ushort>(Crc12Preset.Umts),
                ChecksumAlgo.Crc13 => new Crc<ushort>(Crc13Preset.Default),
                ChecksumAlgo.Crc14 => new Crc<ushort>(Crc14Preset.Default),
                ChecksumAlgo.Crc14Gsm => new Crc<ushort>(Crc14Preset.Gsm),
                ChecksumAlgo.Crc15 => new Crc<ushort>(Crc15Preset.Default),
                ChecksumAlgo.Crc15Mpt1327 => new Crc<ushort>(Crc15Preset.Mpt1327),
                ChecksumAlgo.Crc16 => new Crc<ushort>(),
                ChecksumAlgo.Crc16A => new Crc<ushort>(Crc16Preset.A),
                ChecksumAlgo.Crc16Buypass => new Crc<ushort>(Crc16Preset.Buypass),
                ChecksumAlgo.Crc16Cdma2000 => new Crc<ushort>(Crc16Preset.Cdma2000),
                ChecksumAlgo.Crc16Cms => new Crc<ushort>(Crc16Preset.Cms),
                ChecksumAlgo.Crc16Dds110 => new Crc<ushort>(Crc16Preset.Dds110),
                ChecksumAlgo.Crc16DectR => new Crc<ushort>(Crc16Preset.DectR),
                ChecksumAlgo.Crc16DectX => new Crc<ushort>(Crc16Preset.DectX),
                ChecksumAlgo.Crc16Dnp => new Crc<ushort>(Crc16Preset.Dnp),
                ChecksumAlgo.Crc16En13757 => new Crc<ushort>(Crc16Preset.En13757),
                ChecksumAlgo.Crc16Genibus => new Crc<ushort>(Crc16Preset.Genibus),
                ChecksumAlgo.Crc16Gsm => new Crc<ushort>(Crc16Preset.Gsm),
                ChecksumAlgo.Crc16Ibm3740 => new Crc<ushort>(Crc16Preset.Ibm3740),
                ChecksumAlgo.Crc16IbmSdlc => new Crc<ushort>(Crc16Preset.IbmSdlc),
                ChecksumAlgo.Crc16Kermit => new Crc<ushort>(Crc16Preset.Kermit),
                ChecksumAlgo.Crc16Lj1200 => new Crc<ushort>(Crc16Preset.Lj1200),
                ChecksumAlgo.Crc16Maxim => new Crc<ushort>(Crc16Preset.Maxim),
                ChecksumAlgo.Crc16Mcrf4Xx => new Crc<ushort>(Crc16Preset.Mcrf4Xx),
                ChecksumAlgo.Crc16ModBus => new Crc<ushort>(Crc16Preset.ModBus),
                ChecksumAlgo.Crc16Riello => new Crc<ushort>(Crc16Preset.Riello),
                ChecksumAlgo.Crc16SpiFujitsu => new Crc<ushort>(Crc16Preset.SpiFujitsu),
                ChecksumAlgo.Crc16T10Dif => new Crc<ushort>(Crc16Preset.T10Dif),
                ChecksumAlgo.Crc16TeleDisk => new Crc<ushort>(Crc16Preset.TeleDisk),
                ChecksumAlgo.Crc16Tms37157 => new Crc<ushort>(Crc16Preset.Tms37157),
                ChecksumAlgo.Crc16Usb => new Crc<ushort>(Crc16Preset.Usb),
                ChecksumAlgo.Crc16XModem => new Crc<ushort>(Crc16Preset.XModem),
                ChecksumAlgo.Crc17 => new Crc<uint>(Crc17Preset.Default),
                ChecksumAlgo.Crc21 => new Crc<uint>(Crc21Preset.Default),
                ChecksumAlgo.Crc24 => new Crc<uint>(Crc24Preset.Default),
                ChecksumAlgo.Crc24Ble => new Crc<uint>(Crc24Preset.Ble),
                ChecksumAlgo.Crc24FlexRayA => new Crc<uint>(Crc24Preset.FlexRayA),
                ChecksumAlgo.Crc24FlexRayB => new Crc<uint>(Crc24Preset.FlexRayB),
                ChecksumAlgo.Crc24Interlaken => new Crc<uint>(Crc24Preset.Interlaken),
                ChecksumAlgo.Crc24LteA => new Crc<uint>(Crc24Preset.LteA),
                ChecksumAlgo.Crc24LteB => new Crc<uint>(Crc24Preset.LteB),
                ChecksumAlgo.Crc24Os9 => new Crc<uint>(Crc24Preset.Os9),
                ChecksumAlgo.Crc30 => new Crc<uint>(Crc30Preset.Default),
                ChecksumAlgo.Crc31 => new Crc<uint>(Crc31Preset.Default),
                ChecksumAlgo.Crc32 => new Crc<uint>(),
                ChecksumAlgo.Crc32Autosar => new Crc<uint>(Crc32Preset.Autosar),
                ChecksumAlgo.Crc32BZip2 => new Crc<uint>(Crc32Preset.BZip2),
                ChecksumAlgo.Crc32C => new Crc<uint>(Crc32Preset.C),
                ChecksumAlgo.Crc32CdRomEdc => new Crc<uint>(Crc32Preset.CdRomEdc),
                ChecksumAlgo.Crc32D => new Crc<uint>(Crc32Preset.D),
                ChecksumAlgo.Crc32JamCrc => new Crc<uint>(Crc32Preset.JamCrc),
                ChecksumAlgo.Crc32Mpeg2 => new Crc<uint>(Crc32Preset.Mpeg2),
                ChecksumAlgo.Crc32Posix => new Crc<uint>(Crc32Preset.Posix),
                ChecksumAlgo.Crc32Q => new Crc<uint>(Crc32Preset.Q),
                ChecksumAlgo.Crc32Xfer => new Crc<uint>(Crc32Preset.Xfer),
                ChecksumAlgo.Crc40 => new Crc<ulong>(Crc40Preset.Default),
                ChecksumAlgo.Crc64 => new Crc<ulong>(),
                ChecksumAlgo.Crc64GoIso => new Crc<ulong>(Crc64Preset.GoIso),
                ChecksumAlgo.Crc64We => new Crc<ulong>(Crc64Preset.We),
                ChecksumAlgo.Crc64Xz => new Crc<ulong>(Crc64Preset.Xz),
                ChecksumAlgo.Crc82 => new Crc<BigInteger>(),
                ChecksumAlgo.Md5 => new Md5(),
                ChecksumAlgo.Sha1 => new Sha1(),
                ChecksumAlgo.Sha256 => new Sha256(),
                ChecksumAlgo.Sha384 => new Sha384(),
                ChecksumAlgo.Sha512 => new Sha512(),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null)
            };

        private static IChecksumResult InternalGenericEncrypt<TSource>(TSource source, ChecksumAlgo algorithm, bool ifStreamRestorePos)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            var instance = algorithm.GetDefaultInstance();
            switch (source)
            {
                case BigInteger x:
                    instance.Encrypt(x.ToByteArray());
                    break;
                case char x:
                    instance.Encrypt(x.ToString());
                    break;
                case IEnumerable<byte> x:
                    instance.Encrypt(x as byte[] ?? x.ToArray());
                    break;
                case IEnumerable<char> x:
                    instance.Encrypt(x as string ?? new string(x.ToArray()));
                    break;
                case StreamReader x:
                    LocalProcessStream(instance, x.BaseStream, ifStreamRestorePos);
                    break;
                case Stream x:
                    LocalProcessStream(instance, x, ifStreamRestorePos);
                    break;
                case FileInfo x:
                    instance.Encrypt(x);
                    break;
                default:
#if DEBUG
                    instance.Encrypt(LocalGetByteArray(source));
#else
                    try
                    {
                        instance.Encrypt(LocalGetByteArray(source));
                    }
                    catch (ArgumentException)
                    {
                        // Fallback
                        using var ms = new MemoryStream();
                        using var jw = new Utf8JsonWriter(ms, new JsonWriterOptions { SkipValidation = true });
                        JsonSerializer.Serialize(jw, source);
                        ms.Position = 0L;
                        instance.Encrypt(ms);
                    }
#endif
                    break;
            }
            return instance;

            static byte[] LocalGetByteArray(object value)
            {
                value = value switch
                {
                    bool x => x ? 1 : 0,
                    TimeSpan x => x.TotalMilliseconds,
                    DateTime x => new DateTimeOffset(x).ToUnixTimeMilliseconds(),
                    DateTimeOffset x => x.ToUnixTimeMilliseconds(),
                    _ => value
                };
                var size = Marshal.SizeOf(value);
                var handle = GCHandle.Alloc(value, GCHandleType.Pinned);
                var bytes = new byte[size];
                Marshal.Copy(handle.AddrOfPinnedObject(), bytes, 0, bytes.Length);
                handle.Free();
                return bytes;
            }

            static void LocalProcessStream(IChecksumAlgorithm instance, Stream stream, bool restorePos)
            {
                var pos = restorePos ? stream.Position : -1L;
                instance.Encrypt(stream);
                if (restorePos && pos >= 0)
                    stream.Position = pos;
            }
        }
    }
}
