namespace Roydl.Crypto
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.ComponentModel;
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
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08,

        /// <summary>CRC-8/AUTOSAR.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08Autosar,

        /// <summary>CRC-8/BLUETOOTH.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08Bluetooth,

        /// <summary>CRC-8/CDMA2000.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08Cdma2000,

        /// <summary>CRC-8/DARC.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08Darc,

        /// <summary>CRC-8/DVB-S2.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08DvbS2,

        /// <summary>CRC-8/GSM-A.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08GsmA,

        /// <summary>CRC-8/GSM-B.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08GsmB,

        /// <summary>CRC-8/I-432-1.
        ///     <para><b>Alias:</b> ITU.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08I4321,

        /// <summary>CRC-8/I-CODE.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08ICode,

        /// <summary>CRC-8/LTE.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08Lte,

        /// <summary>CRC-8/MAXIM.
        ///     <para><b>Alias:</b> MAXIM-DOW, DOW-CRC.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08Maxim,

        /// <summary>CRC-8/MIFARE-MAD.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08MifareMad,

        /// <summary>CRC-8/NRSC-5.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08Nrsc5,

        /// <summary>CRC-8/OPENSAFETY.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08OpenSafety,

        /// <summary>CRC-8/ROHC.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08Rohc,

        /// <summary>CRC-8/SAE-J1850.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08SaeJ1850,

        /// <summary>CRC-8/TECH-3250.
        ///     <para><b>Alias:</b> AES, EBU.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08Tech3250,

        /// <summary>CRC-8/WCDMA.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc08Wcdma,

        /// <summary>CRC-10.
        ///     <para><b>Alias:</b> ATM, I-610.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc10,

        /// <summary>CRC-10/CDMA2000.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc10Cdma2000,

        /// <summary>CRC-10/GSM.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc10Gsm,

        /// <summary>CRC-11.
        ///     <para><b>Alias:</b> FLEXRAY.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc11,

        /// <summary>CRC-11/UMTS.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc11Umts,

        /// <summary>CRC-12.
        ///     <para><b>Alias:</b> CDMA2000.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc12,

        /// <summary>CRC-12/DECT.
        ///     <para><b>Alias:</b> X-CRC-12.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc12Dect,

        /// <summary>CRC-12/GSM.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc12Gsm,

        /// <summary>CRC-12/UMTS.
        ///     <para><b>Alias:</b> 3GPP.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc12Umts,

        /// <summary>CRC-13.
        ///     <para><b>Alias:</b> BBC.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc13,

        /// <summary>CRC-14.
        ///     <para><b>Alias:</b> DARC.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc14,

        /// <summary>CRC-14/GSM.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc14Gsm,

        /// <summary>CRC-15.
        ///     <para><b>Alias:</b> CAN.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc15,

        /// <summary>CRC-15/MPT1327.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc15Mpt1327,

        /// <summary>CRC-16.
        ///     <para><b>Alias:</b> ARC, IBM, LHA.</para>
        /// </summary>
        Crc16,

        /// <summary>CRC-16/A.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16A,

        /// <summary>CRC-16/BUYPASS.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Buypass,

        /// <summary>CRC-16/CDMA2000.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Cdma2000,

        /// <summary>CRC-16/CMS.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Cms,

        /// <summary>CRC-16/DDS-110.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Dds110,

        /// <summary>CRC-16/DECT-R.
        ///     <para><b>Alias:</b> R-CRC-16</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16DectR,

        /// <summary>CRC-16/DECT-X.
        ///     <para><b>Alias:</b> X-CRC-16</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16DectX,

        /// <summary>CRC-16/DNP.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Dnp,

        /// <summary>CRC-16/EN-13757.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16En13757,

        /// <summary>CRC-16/GENIBUS.
        ///     <para><b>Alias:</b> DARC, EPC, EPC-C1G2, I-CODE</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Genibus,

        /// <summary>CRC-16/GSM.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Gsm,

        /// <summary>CRC-16/IBM-3740.
        ///     <para><b>Alias:</b> AUTOSAR, CCITT-FALSE</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Ibm3740,

        /// <summary>CRC-16/IBM-SDLC.
        ///     <para><b>Alias:</b> ISO-HDLC, ISO-IEC-14443-3-B, CRC-B, X-25</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16IbmSdlc,

        /// <summary>CRC-16/KERMIT.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Kermit,

        /// <summary>CRC-16/LJ1200.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Lj1200,

        /// <summary>CRC-16/MAXIM.</summary>
        /// <para><b>Alias:</b> MAXIM-DOW</para>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Maxim,

        /// <summary>CRC-16/MCRF4XX.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Mcrf4Xx,

        /// <summary>CRC-16/MODBUS.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16ModBus,

        /// <summary>CRC-16/RIELLO.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Riello,

        /// <summary>CRC-16/SPI-FUJITSU.
        ///     <para><b>Alias:</b> AUG-CCITT</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16SpiFujitsu,

        /// <summary>CRC-16/T10-DIF.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16T10Dif,

        /// <summary>CRC-16/TELEDISK.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16TeleDisk,

        /// <summary>CRC-16/TMS37157.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Tms37157,

        /// <summary>CRC-16/USB.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16Usb,

        /// <summary>CRC-16/XMODEM.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc16XModem,

        /// <summary>CRC-17.
        ///     <para><b>Alias:</b> CAN-FD.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc17,

        /// <summary>CRC-21.
        ///     <para><b>Alias:</b> CAN-FD.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc21,

        /// <summary>CRC-24.
        ///     <para><b>Alias:</b> OPENPGP.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc24,

        /// <summary>CRC-24/BLE.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc24Ble,

        /// <summary>CRC-24/LTE-A.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc24LteA,

        /// <summary>CRC-24/LTE-B.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc24LteB,

        /// <summary>CRC-24/FLEXRAY-A.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc24FlexRayA,

        /// <summary>CRC-24/FLEXRAY-B.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc24FlexRayB,

        /// <summary>CRC-24/INTERLAKEN.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc24Interlaken,

        /// <summary>CRC-24/OS-9.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc24Os9,

        /// <summary>CRC-30.
        ///     <para><b>Alias:</b> CDMA.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc30,

        /// <summary>CRC-31.
        ///     <para><b>Alias:</b> PHILIPS.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc31,

        /// <summary>CRC-32/ISO-HDLC.
        ///     <para><b>Alias:</b> ADCCP, ISO-HDLC, PKZip, V-24, XZ.</para>
        /// </summary>
        Crc32,

        /// <summary>CRC-32/AUTOSAR.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc32Autosar,

        /// <summary>CRC-32/CD-ROM-EDC.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc32CdRomEdc,

        /// <summary>CRC-32/Q.
        ///     <para><b>Alias:</b> AIXM.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc32Q,

        /// <summary>CRC-32/BZIP2.
        ///     <para><b>Alias:</b> AAL5, DECT-B, B-CRC.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc32BZip2,

        /// <summary>CRC-32/C.
        ///     <para><b>Alias:</b> BASE91-C, Castagnoli, Interlaken, ISCSI.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc32C,

        /// <summary>CRC-32/D.
        ///     <para><b>Alias:</b> BASE91-D.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc32D,

        /// <summary>CRC-32/JAMCRC.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc32JamCrc,

        /// <summary>CRC-32/MPEG-2.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc32Mpeg2,

        /// <summary>CRC-32/POSIX.
        ///     <para><b>Alias:</b> CKSUM.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc32Posix,

        /// <summary>CRC-32/XFER.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc32Xfer,

        /// <summary>CRC-40.
        ///     <para><b>Alias:</b> GSM.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc40,

        /// <summary>CRC-64.
        ///     <para><b>Alias:</b> ECMA-182.</para>
        /// </summary>
        Crc64,

        /// <summary>CRC-64/WE.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc64We,

        /// <summary>CRC-64/XZ.
        ///     <para><b>Alias:</b> GO-ECMA.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc64Xz,

        /// <summary>CRC-64/GO-ISO.</summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc64GoIso,

        /// <summary>CRC-82.
        ///     <para><b>Alias:</b> DARC.</para>
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        Crc82,

        /// <summary>MD5-128.</summary>
        Md5,

        /// <summary>SHA-1-160.</summary>
        Sha1,

        /// <summary>SHA-2-256.</summary>
        Sha256,

        /// <summary>SHA-2-384.</summary>
        Sha384,

        /// <summary>SHA-2-512.</summary>
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
            algorithm.GetDefaultInstance().InternalEncrypt(source, false) switch
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
            algorithm.GetDefaultInstance().InternalEncrypt(source, false).Hash;

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
        public static unsafe string GetGuid<TSource>(this TSource source, bool braces = false, ChecksumAlgo algorithm1 = ChecksumAlgo.Crc32, ChecksumAlgo algorithm2 = ChecksumAlgo.Sha256)
        {
            var span1 = algorithm1.GetDefaultInstance().InternalEncrypt(source, true).RawHash.Span;
            var span2 = algorithm2.GetDefaultInstance().InternalEncrypt(source, false).RawHash.Span;
            string str;
            fixed (byte* rawIn1 = &span1[0], rawIn2 = &span2[0])
            {
                Span<byte> rawOut = stackalloc byte[16];
                var len1 = span1.Length;
                var len2 = span2.Length;
                var i1 = 0;
                var i2 = 0;
                for (var i = 0; i < 16; i++)
                {
                    ref var e1 = ref rawIn1[i1 < len1 ? i1++ : i1 = 0];
                    ref var e2 = ref rawIn2[i2 < len2 ? i2++ : i2 = 0];
                    rawOut[i] = (byte)CryptoUtils.CombineHashCodes(e1, e2);
                }
                var sb = new StringBuilder(braces ? 38 : 36);
                if (braces)
                    sb.Append('{');
                i1 = 0;
                for (var i = 0; i < 5; i++)
                {
                    var width = i < 1 ? 4 : i >= 4 ? 6 : 2;
                    for (var j = 0; j < width; j++)
                        sb.AppendFormat("{0:x2}", rawOut[i1++]);
                    if (i < 4)
                        sb.Append('-');
                }
                if (braces)
                    sb.Append('}');
                str = sb.ToString();
                sb.Clear();
            }
            return str;
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
                ChecksumAlgo.Adler32 => Adler32.Create(),
                ChecksumAlgo.Crc08 => Crc.Create(CrcOptions.Crc.Default),
                ChecksumAlgo.Crc08Autosar => Crc.Create(CrcOptions.Crc.Autosar),
                ChecksumAlgo.Crc08Bluetooth => Crc.Create(CrcOptions.Crc.Bluetooth),
                ChecksumAlgo.Crc08Cdma2000 => Crc.Create(CrcOptions.Crc.Cdma2000),
                ChecksumAlgo.Crc08Darc => Crc.Create(CrcOptions.Crc.Darc),
                ChecksumAlgo.Crc08DvbS2 => Crc.Create(CrcOptions.Crc.DvbS2),
                ChecksumAlgo.Crc08GsmA => Crc.Create(CrcOptions.Crc.GsmA),
                ChecksumAlgo.Crc08GsmB => Crc.Create(CrcOptions.Crc.GsmB),
                ChecksumAlgo.Crc08I4321 => Crc.Create(CrcOptions.Crc.I4321),
                ChecksumAlgo.Crc08ICode => Crc.Create(CrcOptions.Crc.ICode),
                ChecksumAlgo.Crc08Lte => Crc.Create(CrcOptions.Crc.Lte),
                ChecksumAlgo.Crc08Maxim => Crc.Create(CrcOptions.Crc.Maxim),
                ChecksumAlgo.Crc08MifareMad => Crc.Create(CrcOptions.Crc.MifareMad),
                ChecksumAlgo.Crc08Nrsc5 => Crc.Create(CrcOptions.Crc.Nrsc5),
                ChecksumAlgo.Crc08OpenSafety => Crc.Create(CrcOptions.Crc.OpenSafety),
                ChecksumAlgo.Crc08Rohc => Crc.Create(CrcOptions.Crc.Rohc),
                ChecksumAlgo.Crc08SaeJ1850 => Crc.Create(CrcOptions.Crc.SaeJ1850),
                ChecksumAlgo.Crc08Tech3250 => Crc.Create(CrcOptions.Crc.Tech3250),
                ChecksumAlgo.Crc08Wcdma => Crc.Create(CrcOptions.Crc.Wcdma),
                ChecksumAlgo.Crc10 => Crc.Create(CrcOptions.Crc10.Default),
                ChecksumAlgo.Crc10Cdma2000 => Crc.Create(CrcOptions.Crc10.Cdma2000),
                ChecksumAlgo.Crc10Gsm => Crc.Create(CrcOptions.Crc10.Gsm),
                ChecksumAlgo.Crc11 => Crc.Create(CrcOptions.Crc11.Default),
                ChecksumAlgo.Crc11Umts => Crc.Create(CrcOptions.Crc11.Umts),
                ChecksumAlgo.Crc12 => Crc.Create(CrcOptions.Crc12.Default),
                ChecksumAlgo.Crc12Dect => Crc.Create(CrcOptions.Crc12.Dect),
                ChecksumAlgo.Crc12Gsm => Crc.Create(CrcOptions.Crc12.Gsm),
                ChecksumAlgo.Crc12Umts => Crc.Create(CrcOptions.Crc12.Umts),
                ChecksumAlgo.Crc13 => Crc.Create(CrcOptions.Crc13.Default),
                ChecksumAlgo.Crc14 => Crc.Create(CrcOptions.Crc14.Default),
                ChecksumAlgo.Crc14Gsm => Crc.Create(CrcOptions.Crc14.Gsm),
                ChecksumAlgo.Crc15 => Crc.Create(CrcOptions.Crc15.Default),
                ChecksumAlgo.Crc15Mpt1327 => Crc.Create(CrcOptions.Crc15.Mpt1327),
                ChecksumAlgo.Crc16 => Crc.Create(CrcOptions.Crc16.Default),
                ChecksumAlgo.Crc16A => Crc.Create(CrcOptions.Crc16.A),
                ChecksumAlgo.Crc16Buypass => Crc.Create(CrcOptions.Crc16.Buypass),
                ChecksumAlgo.Crc16Cdma2000 => Crc.Create(CrcOptions.Crc16.Cdma2000),
                ChecksumAlgo.Crc16Cms => Crc.Create(CrcOptions.Crc16.Cms),
                ChecksumAlgo.Crc16Dds110 => Crc.Create(CrcOptions.Crc16.Dds110),
                ChecksumAlgo.Crc16DectR => Crc.Create(CrcOptions.Crc16.DectR),
                ChecksumAlgo.Crc16DectX => Crc.Create(CrcOptions.Crc16.DectX),
                ChecksumAlgo.Crc16Dnp => Crc.Create(CrcOptions.Crc16.Dnp),
                ChecksumAlgo.Crc16En13757 => Crc.Create(CrcOptions.Crc16.En13757),
                ChecksumAlgo.Crc16Genibus => Crc.Create(CrcOptions.Crc16.Genibus),
                ChecksumAlgo.Crc16Gsm => Crc.Create(CrcOptions.Crc16.Gsm),
                ChecksumAlgo.Crc16Ibm3740 => Crc.Create(CrcOptions.Crc16.Ibm3740),
                ChecksumAlgo.Crc16IbmSdlc => Crc.Create(CrcOptions.Crc16.IbmSdlc),
                ChecksumAlgo.Crc16Kermit => Crc.Create(CrcOptions.Crc16.Kermit),
                ChecksumAlgo.Crc16Lj1200 => Crc.Create(CrcOptions.Crc16.Lj1200),
                ChecksumAlgo.Crc16Maxim => Crc.Create(CrcOptions.Crc16.Maxim),
                ChecksumAlgo.Crc16Mcrf4Xx => Crc.Create(CrcOptions.Crc16.Mcrf4Xx),
                ChecksumAlgo.Crc16ModBus => Crc.Create(CrcOptions.Crc16.ModBus),
                ChecksumAlgo.Crc16Riello => Crc.Create(CrcOptions.Crc16.Riello),
                ChecksumAlgo.Crc16SpiFujitsu => Crc.Create(CrcOptions.Crc16.SpiFujitsu),
                ChecksumAlgo.Crc16T10Dif => Crc.Create(CrcOptions.Crc16.T10Dif),
                ChecksumAlgo.Crc16TeleDisk => Crc.Create(CrcOptions.Crc16.TeleDisk),
                ChecksumAlgo.Crc16Tms37157 => Crc.Create(CrcOptions.Crc16.Tms37157),
                ChecksumAlgo.Crc16Usb => Crc.Create(CrcOptions.Crc16.Usb),
                ChecksumAlgo.Crc16XModem => Crc.Create(CrcOptions.Crc16.XModem),
                ChecksumAlgo.Crc17 => Crc.Create(CrcOptions.Crc17.Default),
                ChecksumAlgo.Crc21 => Crc.Create(CrcOptions.Crc21.Default),
                ChecksumAlgo.Crc24 => Crc.Create(CrcOptions.Crc24.Default),
                ChecksumAlgo.Crc24Ble => Crc.Create(CrcOptions.Crc24.Ble),
                ChecksumAlgo.Crc24FlexRayA => Crc.Create(CrcOptions.Crc24.FlexRayA),
                ChecksumAlgo.Crc24FlexRayB => Crc.Create(CrcOptions.Crc24.FlexRayB),
                ChecksumAlgo.Crc24Interlaken => Crc.Create(CrcOptions.Crc24.Interlaken),
                ChecksumAlgo.Crc24LteA => Crc.Create(CrcOptions.Crc24.LteA),
                ChecksumAlgo.Crc24LteB => Crc.Create(CrcOptions.Crc24.LteB),
                ChecksumAlgo.Crc24Os9 => Crc.Create(CrcOptions.Crc24.Os9),
                ChecksumAlgo.Crc30 => Crc.Create(CrcOptions.Crc30.Default),
                ChecksumAlgo.Crc31 => Crc.Create(CrcOptions.Crc31.Default),
                ChecksumAlgo.Crc32 => Crc.Create(CrcOptions.Crc32.Default),
                ChecksumAlgo.Crc32Autosar => Crc.Create(CrcOptions.Crc32.Autosar),
                ChecksumAlgo.Crc32BZip2 => Crc.Create(CrcOptions.Crc32.BZip2),
                ChecksumAlgo.Crc32C => Crc.Create(CrcOptions.Crc32.C),
                ChecksumAlgo.Crc32CdRomEdc => Crc.Create(CrcOptions.Crc32.CdRomEdc),
                ChecksumAlgo.Crc32D => Crc.Create(CrcOptions.Crc32.D),
                ChecksumAlgo.Crc32JamCrc => Crc.Create(CrcOptions.Crc32.JamCrc),
                ChecksumAlgo.Crc32Mpeg2 => Crc.Create(CrcOptions.Crc32.Mpeg2),
                ChecksumAlgo.Crc32Posix => Crc.Create(CrcOptions.Crc32.Posix),
                ChecksumAlgo.Crc32Q => Crc.Create(CrcOptions.Crc32.Q),
                ChecksumAlgo.Crc32Xfer => Crc.Create(CrcOptions.Crc32.Xfer),
                ChecksumAlgo.Crc40 => Crc.Create(CrcOptions.Crc40.Default),
                ChecksumAlgo.Crc64 => Crc.Create(CrcOptions.Crc64.Default),
                ChecksumAlgo.Crc64GoIso => Crc.Create(CrcOptions.Crc64.GoIso),
                ChecksumAlgo.Crc64We => Crc.Create(CrcOptions.Crc64.We),
                ChecksumAlgo.Crc64Xz => Crc.Create(CrcOptions.Crc64.Xz),
                ChecksumAlgo.Crc82 => Crc.Create(CrcOptions.Crc82.Default),
                ChecksumAlgo.Md5 => Md5.Create(),
                ChecksumAlgo.Sha1 => Sha1.Create(),
                ChecksumAlgo.Sha256 => Sha256.Create(),
                ChecksumAlgo.Sha384 => Sha384.Create(),
                ChecksumAlgo.Sha512 => Sha512.Create(),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null)
            };

        internal static IChecksumResult InternalEncrypt<TSource>(this IChecksumAlgorithm instance, TSource source, bool restoreStreamPos)
        {
            if (instance == null)
                throw new ArgumentNullException(nameof(instance));
            if (source == null)
                throw new ArgumentNullException(nameof(source));
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
                case Memory<byte> x:
                    instance.Encrypt(x.Span);
                    break;
                case ReadOnlySequence<byte> x:
                    instance.Encrypt(x.FirstSpan);
                    break;
                case ReadOnlySequenceSegment<byte> x:
                    instance.Encrypt(x.Memory.Span);
                    break;
                case IEnumerable<char> x:
                    instance.Encrypt(x as string ?? new string(x.ToArray()));
                    break;
                case Memory<char> x:
                    instance.Encrypt(new string(x.Span));
                    break;
                case ReadOnlySequence<char> x:
                    instance.Encrypt(new string(x.FirstSpan));
                    break;
                case ReadOnlySequenceSegment<char> x:
                    instance.Encrypt(new string(x.Memory.Span));
                    break;
                case StreamReader x:
                    LocalProcessStream(instance, x.BaseStream, restoreStreamPos);
                    break;
                case Stream x:
                    LocalProcessStream(instance, x, restoreStreamPos);
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
