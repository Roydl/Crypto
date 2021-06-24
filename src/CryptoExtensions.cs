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
    using System.Security;
    using System.Text;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using Checksum;
    using Internal;
    using Resources;

    /// <summary>Specifies enumerated constants used to define an algorithm for encrypting data.</summary>
    /// <remarks>Note that most of the CRC constants are tagged with <see cref="EditorBrowsableState.Never"/>. You are able to find all available names by performing a <see langword="Go To Definition"/> on <see cref="ChecksumAlgo"/>. It is also possible to convert <see cref="CrcOptions"/> to <see cref="ChecksumAlgo"/>.</remarks>
    public enum ChecksumAlgo
    {
        /// ReSharper disable CommentTypo
        /// <summary>Adler-32.</summary>
        /// <remarks><b>Performance</b>: Highly optimized. Faster than non-optimized CRC algorithms, but slower than optimized ones.</remarks>
        Adler32,

        #region CRC-8

        /// <inheritdoc cref="CrcOptions.Crc.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8,

        /// <inheritdoc cref="CrcOptions.Crc.Autosar"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8Autosar,

        /// <inheritdoc cref="CrcOptions.Crc.Bluetooth"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8Bluetooth,

        /// <inheritdoc cref="CrcOptions.Crc.Cdma2000"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8Cdma2000,

        /// <inheritdoc cref="CrcOptions.Crc.Darc"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8Darc,

        /// <inheritdoc cref="CrcOptions.Crc.DvbS2"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8DvbS2,

        /// <inheritdoc cref="CrcOptions.Crc.GsmA"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8GsmA,

        /// <inheritdoc cref="CrcOptions.Crc.GsmB"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8GsmB,

        /// <inheritdoc cref="CrcOptions.Crc.I4321"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8I4321,

        /// <inheritdoc cref="CrcOptions.Crc.ICode"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8ICode,

        /// <inheritdoc cref="CrcOptions.Crc.Lte"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8Lte,

        /// <inheritdoc cref="CrcOptions.Crc.Maxim"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8Maxim,

        /// <inheritdoc cref="CrcOptions.Crc.MifareMad"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8MifareMad,

        /// <inheritdoc cref="CrcOptions.Crc.Nrsc5"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8Nrsc5,

        /// <inheritdoc cref="CrcOptions.Crc.OpenSafety"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8OpenSafety,

        /// <inheritdoc cref="CrcOptions.Crc.Rohc"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8Rohc,

        /// <inheritdoc cref="CrcOptions.Crc.SaeJ1850"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8SaeJ1850,

        /// <inheritdoc cref="CrcOptions.Crc.Tech3250"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8Tech3250,

        /// <inheritdoc cref="CrcOptions.Crc.Wcdma"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc8Wcdma,

        #endregion

        #region CRC-10 to CRC-15

        /// <inheritdoc cref="CrcOptions.Crc10.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc10,

        /// <inheritdoc cref="CrcOptions.Crc10.Cdma2000"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc10Cdma2000,

        /// <inheritdoc cref="CrcOptions.Crc10.Gsm"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc10Gsm,

        /// <inheritdoc cref="CrcOptions.Crc11.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc11,

        /// <inheritdoc cref="CrcOptions.Crc11.Umts"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc11Umts,

        /// <inheritdoc cref="CrcOptions.Crc12.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc12,

        /// <inheritdoc cref="CrcOptions.Crc12.Dect"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc12Dect,

        /// <inheritdoc cref="CrcOptions.Crc12.Gsm"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc12Gsm,

        /// <inheritdoc cref="CrcOptions.Crc12.Umts"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc12Umts,

        /// <inheritdoc cref="CrcOptions.Crc13.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc13,

        /// <inheritdoc cref="CrcOptions.Crc14.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc14,

        /// <inheritdoc cref="CrcOptions.Crc14.Gsm"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc14Gsm,

        /// <inheritdoc cref="CrcOptions.Crc15.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc15,

        /// <inheritdoc cref="CrcOptions.Crc15.Mpt1327"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc15Mpt1327,

        #endregion

        #region CRC-16

        /// <inheritdoc cref="CrcOptions.Crc16.Default"/>
        Crc16,

        /// <inheritdoc cref="CrcOptions.Crc16.A"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16A,

        /// <inheritdoc cref="CrcOptions.Crc16.Buypass"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Buypass,

        /// <inheritdoc cref="CrcOptions.Crc16.Cdma2000"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Cdma2000,

        /// <inheritdoc cref="CrcOptions.Crc16.Cms"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Cms,

        /// <inheritdoc cref="CrcOptions.Crc16.Dds110"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Dds110,

        /// <inheritdoc cref="CrcOptions.Crc16.DectR"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16DectR,

        /// <inheritdoc cref="CrcOptions.Crc16.DectX"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16DectX,

        /// <inheritdoc cref="CrcOptions.Crc16.Dnp"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Dnp,

        /// <inheritdoc cref="CrcOptions.Crc16.En13757"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16En13757,

        /// <inheritdoc cref="CrcOptions.Crc16.Genibus"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Genibus,

        /// <inheritdoc cref="CrcOptions.Crc16.Gsm"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Gsm,

        /// <inheritdoc cref="CrcOptions.Crc16.Ibm3740"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Ibm3740,

        /// <inheritdoc cref="CrcOptions.Crc16.IbmSdlc"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16IbmSdlc,

        /// <inheritdoc cref="CrcOptions.Crc16.Kermit"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Kermit,

        /// <inheritdoc cref="CrcOptions.Crc16.Lj1200"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Lj1200,

        /// <inheritdoc cref="CrcOptions.Crc16.Maxim"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Maxim,

        /// <inheritdoc cref="CrcOptions.Crc16.Mcrf4Xx"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Mcrf4Xx,

        /// <inheritdoc cref="CrcOptions.Crc16.ModBus"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16ModBus,

        /// <inheritdoc cref="CrcOptions.Crc16.Riello"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Riello,

        /// <inheritdoc cref="CrcOptions.Crc16.SpiFujitsu"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16SpiFujitsu,

        /// <inheritdoc cref="CrcOptions.Crc16.T10Dif"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16T10Dif,

        /// <inheritdoc cref="CrcOptions.Crc16.TeleDisk"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16TeleDisk,

        /// <inheritdoc cref="CrcOptions.Crc16.Tms37157"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Tms37157,

        /// <inheritdoc cref="CrcOptions.Crc16.Usb"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16Usb,

        /// <inheritdoc cref="CrcOptions.Crc16.XModem"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc16XModem,

        #endregion

        #region CRC-17 to CRC-31

        /// <inheritdoc cref="CrcOptions.Crc17.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc17,

        /// <inheritdoc cref="CrcOptions.Crc21.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc21,

        /// <inheritdoc cref="CrcOptions.Crc24.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc24,

        /// <inheritdoc cref="CrcOptions.Crc24.Ble"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc24Ble,

        /// <inheritdoc cref="CrcOptions.Crc24.LteA"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc24LteA,

        /// <inheritdoc cref="CrcOptions.Crc24.LteB"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc24LteB,

        /// <inheritdoc cref="CrcOptions.Crc24.FlexRayA"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc24FlexRayA,

        /// <inheritdoc cref="CrcOptions.Crc24.FlexRayB"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc24FlexRayB,

        /// <inheritdoc cref="CrcOptions.Crc24.Interlaken"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc24Interlaken,

        /// <inheritdoc cref="CrcOptions.Crc24.Os9"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc24Os9,

        /// <inheritdoc cref="CrcOptions.Crc30.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc30,

        /// <inheritdoc cref="CrcOptions.Crc31.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc31,

        #endregion

        #region CRC-32

        /// <inheritdoc cref="CrcOptions.Crc32.Default"/>
        Crc32,

        /// <inheritdoc cref="CrcOptions.Crc32.Autosar"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc32Autosar,

        /// <inheritdoc cref="CrcOptions.Crc32.CdRomEdc"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc32CdRomEdc,

        /// <inheritdoc cref="CrcOptions.Crc32.Q"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc32Q,

        /// <inheritdoc cref="CrcOptions.Crc32.BZip2"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc32BZip2,

        /// <inheritdoc cref="CrcOptions.Crc32.D"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc32D,

        /// <inheritdoc cref="CrcOptions.Crc32.JamCrc"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc32JamCrc,

        /// <inheritdoc cref="CrcOptions.Crc32.Mpeg2"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc32Mpeg2,

        /// <inheritdoc cref="CrcOptions.Crc32.Posix"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc32Posix,

        /// <inheritdoc cref="CrcOptions.Crc32.Xfer"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc32Xfer,

        /// <inheritdoc cref="CrcOptions.Crc32.Xz"/>
        Crc32Xz,

        #endregion

        #region CRC-40 to CRC-82

        /// <inheritdoc cref="CrcOptions.Crc40.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc40,

        /// <inheritdoc cref="CrcOptions.Crc64.Default"/>
        Crc64,

        /// <inheritdoc cref="CrcOptions.Crc64.We"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc64We,

        /// <inheritdoc cref="CrcOptions.Crc64.Xz"/>
        Crc64Xz,

        /// <inheritdoc cref="CrcOptions.Crc64.GoIso"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc64GoIso,

        /// <inheritdoc cref="CrcOptions.Crc82.Default"/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        Crc82,

        #endregion

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
        /// <summary>Hashes this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns the 64-bit unsigned integer representation of the computed hash code.</summary>
        /// <exception cref="ArgumentNullException">source is null.</exception>
        /// <exception cref="ArgumentException">source is empty.</exception>
        /// <exception cref="FileNotFoundException">source cannot be found.</exception>
        /// <exception cref="UnauthorizedAccessException">source is a directory.</exception>
        /// <exception cref="IOException">source is already open, or an I/O error occurs.</exception>
        /// <exception cref="NotSupportedException">source does not support reading.</exception>
        /// <returns>A 64-bit unsigned integer that contains the result of hashing the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>.</returns>
        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static ulong GetCipher<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            var instance = algorithm.GetDefaultInstance();
            return instance.InternalComputeHash(source, false) switch
            {
                IChecksumResult<byte> x => x.CipherHash,
                IChecksumResult<ushort> x => x.CipherHash,
                IChecksumResult<uint> x => x.CipherHash,
                IChecksumResult<ulong> x => x.CipherHash,
                IChecksumResult<BigInteger> x => (ulong)(x.CipherHash & ulong.MaxValue),
                _ => default
            };
        }

        /// <summary>Hashes this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns the string representation of the computed hash code.</summary>
        /// <returns>A string that contains the result of hashing the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>.</returns>
        /// <inheritdoc cref="GetCipher{TSource}(TSource, ChecksumAlgo)"/>
        [return: NotNullIfNotNull("source")]
        public static string GetChecksum<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256) =>
            algorithm.GetDefaultInstance().InternalComputeHash(source, false).Hash;

        /// <summary>Hashes the file at this <paramref name="path"/> with the specified <paramref name="algorithm"/> and returns the string representation of the computed hash code.</summary>
        /// <param name="path">The full path of the file to hash.</param>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <returns>A string that contains the result of hashing the file at specified <paramref name="path"/> by the specified <paramref name="algorithm"/>.</returns>
        /// <inheritdoc cref="IChecksumAlgorithm.ComputeFileHash(string)"/>
        public static string GetFileChecksum(this string path, ChecksumAlgo algorithm = ChecksumAlgo.Sha256)
        {
            if (path == null)
                throw new ArgumentNullException(nameof(path));
            if (!File.Exists(path))
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, path);
            var instance = algorithm.GetDefaultInstance();
            instance.ComputeFileHash(path);
            return instance.Hash;
        }

        /// <summary>Hashes all files of this <paramref name="dirInfo"/> object with the specified <paramref name="algorithm"/>.</summary>
        /// <exception cref="ArgumentNullException">dirInfo is null.</exception>
        /// <exception cref="DirectoryNotFoundException">The path encapsulated in dirInfo is invalid, such as being on an unmapped drive.</exception>
        /// <exception cref="SecurityException">The caller does not have the required permission.</exception>
        /// <exception cref="UnauthorizedAccessException">The caller does not have the required permission.</exception>
        /// <exception cref="IOException">A device such as a disk drive is not ready, or an I/O error occurs.</exception>
        /// <exception cref="NotSupportedException">A file does not support reading.</exception>
        /// <returns>A sequence of <see cref="string"/>-based <see cref="KeyValuePair"/>&lt;<see langword="FilePath"/>, <see langword="Checksum"/>&gt; objects provided by an <see cref="IDictionary{TKey, TValue}"/> object that contains the result of hashing the files of the specified <paramref name="dirInfo"/> by the specified <paramref name="algorithm"/>.</returns>
        /// <inheritdoc cref="TryGetChecksums(DirectoryInfo, SearchOption, ChecksumAlgo, out IDictionary{string, string})"/>
        [return: NotNullIfNotNull("dirInfo")]
        public static IDictionary<string, string> GetChecksums(this DirectoryInfo dirInfo, SearchOption searchOption = SearchOption.AllDirectories, ChecksumAlgo algorithm = ChecksumAlgo.Sha256)
        {
            if (dirInfo == null)
                throw new ArgumentNullException(nameof(dirInfo));
            dirInfo.Refresh();
            if (!dirInfo.Exists)
                throw new DirectoryNotFoundException();
            var files = dirInfo.GetFiles();
            var capacity = GetCapacity(files.Length, dirInfo, searchOption);
            if (capacity == 0)
                return new Dictionary<string, string>();
            var items = new KeyValuePair<string, string>[capacity];
            var index = -1;
            if (files.Any())
                Parallel.ForEach(files, fi =>
                {
                    var i = Interlocked.Increment(ref index);
                    items[i] = new KeyValuePair<string, string>(fi.FullName, fi.GetChecksum(algorithm));
                });
            DirectoryInfo[] dirs;
            if (searchOption == SearchOption.AllDirectories && capacity > files.Length && (dirs = dirInfo.GetDirectories()).Any())
                Parallel.ForEach(dirs, di =>
                {
                    var dict = di.GetChecksums(algorithm);
                    Parallel.ForEach(dict, pair =>
                    {
                        var i = Interlocked.Increment(ref index);
                        items[i] = pair;
                    });
                });
            return items.OrderBy(p => p.Key, StringComparer.Ordinal).ToDictionary(p => p.Key, p => p.Value);

            static int GetCapacity(int numberOfFiles, DirectoryInfo dirInfo, SearchOption searchOption)
            {
                var count = numberOfFiles;
                if (searchOption == SearchOption.TopDirectoryOnly)
                    return numberOfFiles;
                var dirs = dirInfo.GetDirectories();
                if (dirs.Any())
                    Parallel.ForEach(dirs, di => Interlocked.Add(ref count, GetCapacity(di.GetFiles().Length, di, SearchOption.AllDirectories)));
                return count;
            }
        }

        /// <inheritdoc cref="GetChecksums(DirectoryInfo, SearchOption, ChecksumAlgo)"/>
        [return: NotNullIfNotNull("dirInfo")]
        public static IDictionary<string, string> GetChecksums(this DirectoryInfo dirInfo, ChecksumAlgo algorithm) =>
            GetChecksums(dirInfo, SearchOption.AllDirectories, algorithm);

        /// <summary>Hashes this <paramref name="source"/> object with the specified <paramref name="algorithm1"/> and the specified <paramref name="algorithm2"/> and combines the bytes of both hashes into a unique GUID string.</summary>
        /// <param name="source">The object to hash.</param>
        /// <param name="braces"><see langword="true"/> to place the GUID between braces; otherwise, <see langword="false"/>.</param>
        /// <param name="algorithm1">The first algorithm to use.</param>
        /// <param name="algorithm2">The second algorithm to use.</param>
        /// <returns>A string with a GUID that contains the results of encrypting the specified <paramref name="source"/> object by the specified <paramref name="algorithm1"/> and the specified <paramref name="algorithm2"/>.</returns>
        /// <inheritdoc cref="GetCipher{TSource}(TSource, ChecksumAlgo)"/>
        [return: NotNullIfNotNull("source")]
        public static unsafe string GetGuid<TSource>(this TSource source, bool braces = false, ChecksumAlgo algorithm1 = ChecksumAlgo.Crc32, ChecksumAlgo algorithm2 = ChecksumAlgo.Sha256)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            var inst1 = algorithm1.GetDefaultInstance();
            var inst2 = algorithm2.GetDefaultInstance();
            var span1 = inst1.InternalComputeHash(source, true).RawHash;
            var span2 = inst2.InternalComputeHash(source, false).RawHash;
            string str;
            fixed (byte* rawIn1 = span1, rawIn2 = span2)
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
                var hx = NumericHelper.HexLookupLower;
                var sb = new StringBuilder(braces ? 38 : 36);
                if (braces)
                    sb.Append('{');
                i1 = 0;
                for (var i = 0; i < 5; i++)
                {
                    var width = i < 1 ? 4 : i >= 4 ? 6 : 2;
                    for (var j = 0; j < width; j++)
                    {
                        var b = rawOut[i1++];
                        sb.Append(hx[b >> 4]);
                        sb.Append(hx[b & 0xf]);
                    }
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
        /// <summary>Tries to hash this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns a <see cref="bool"/> value that determines whether the task was successful. All possible exceptions are caught.</summary>
        /// <typeparam name="TSource">The type of source.</typeparam>
        /// <param name="source">The object to hash.</param>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <param name="hash">If successful, the result of hashing the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>; otherwise, <see langword="default"/>.</param>
        /// <remarks>
        ///     <list type="table">
        ///         <item><term>Known</term> <description><see cref="bool"/>, <see cref="sbyte"/>, <see cref="byte"/>, <see cref="short"/>, <see cref="ushort"/>, <see cref="char"/>, <see cref="int"/>, <see cref="uint"/>, <see cref="long"/>, <see cref="ulong"/>, <see cref="Half"/>, <see cref="float"/>, <see cref="double"/>, <see cref="decimal"/>, <see cref="Enum"/>, <see cref="IntPtr"/>, <see cref="UIntPtr"/>, <see cref="Vector{T}"/>, <see cref="Vector2"/>, <see cref="Vector3"/>, <see cref="Vector4"/>, <see cref="Matrix3x2"/>, <see cref="Matrix4x4"/>, <see cref="Plane"/>, <see cref="Quaternion"/>, <see cref="Complex"/>, <see cref="BigInteger"/>, <see cref="DateTime"/>, <see cref="DateTimeOffset"/>, <see cref="TimeSpan"/>, <see cref="Guid"/>, <see cref="Rune"/>, <see cref="Stream"/>, <see cref="StreamReader"/>, <see cref="FileInfo"/>, any <see cref="IEnumerable{T}"/> <see cref="byte"/> sequence, i.e. <see cref="Array"/>, or any <see cref="IEnumerable{T}"/> <see cref="char"/> sequence, i.e. <see cref="string"/>.</description></item>
        ///         <item><term>Otherwise</term> <description>An attempt is made to convert <paramref name="source"/> to a byte array for the encryption, which should work for all <see href="https://docs.microsoft.com/en-us/dotnet/framework/interop/blittable-and-non-blittable-types">blittable types</see>. If this fails, <paramref name="source"/> is serialized using <see cref="Utf8JsonWriter"/> and the result is encrypted.</description></item>
        ///     </list>
        /// </remarks>
        /// <returns><see langword="true"/> if the specified <paramref name="source"/> could be hashed by the specified <paramref name="algorithm"/>; otherwise, <see langword="false"/>.</returns>
#else
        /// <summary>Tries to hash this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns a <see cref="bool"/> value that determines whether the task was successful. All possible exceptions are caught.</summary>
        /// <typeparam name="TSource">The type of source.</typeparam>
        /// <param name="source">The object to hash.</param>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <param name="hash">If successful, the result of hashing the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>; otherwise, <see langword="default"/>.</param>
        /// <remarks>
        ///     <list type="table">
        ///         <item><term>Known</term> <description><see cref="bool"/>, <see cref="sbyte"/>, <see cref="byte"/>, <see cref="short"/>, <see cref="ushort"/>, <see cref="char"/>, <see cref="int"/>, <see cref="uint"/>, <see cref="long"/>, <see cref="ulong"/>, <see cref="float"/>, <see cref="double"/>, <see cref="decimal"/>, <see cref="Enum"/>, <see cref="IntPtr"/>, <see cref="UIntPtr"/>, <see cref="Vector{T}"/>, <see cref="Vector2"/>, <see cref="Vector3"/>, <see cref="Vector4"/>, <see cref="Matrix3x2"/>, <see cref="Matrix4x4"/>, <see cref="Plane"/>, <see cref="Quaternion"/>, <see cref="Complex"/>, <see cref="BigInteger"/>, <see cref="DateTime"/>, <see cref="DateTimeOffset"/>, <see cref="TimeSpan"/>, <see cref="Guid"/>, <see cref="Rune"/>, <see cref="Stream"/>, <see cref="StreamReader"/>, <see cref="FileInfo"/>, any <see cref="IEnumerable{T}"/> <see cref="byte"/> sequence, i.e. <see cref="Array"/>, or any <see cref="IEnumerable{T}"/> <see cref="char"/> sequence, i.e. <see cref="string"/>.</description></item>
        ///         <item><term>Otherwise</term> <description>An attempt is made to convert <paramref name="source"/> to a byte array for the encryption, which should work for all <see href="https://docs.microsoft.com/en-us/dotnet/framework/interop/blittable-and-non-blittable-types">blittable types</see>. If this fails, <paramref name="source"/> is serialized using <see cref="Utf8JsonWriter"/> and the result is encrypted.</description></item>
        ///     </list>
        /// </remarks>
        /// <returns><see langword="true"/> if the specified <paramref name="source"/> could be hashed by the specified <paramref name="algorithm"/>; otherwise, <see langword="false"/>.</returns>
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

        /// <summary>Tries to hash this <paramref name="source"/> object with the <see cref="ChecksumAlgo.Sha256"/> algorithm and returns a <see cref="bool"/> value that determines whether the task was successful. All possible exceptions are caught.</summary>
        /// <typeparam name="TSource">The type of source.</typeparam>
        /// <param name="source">The object to hash.</param>
        /// <param name="hash">If successful, the result of hashing the specified <paramref name="source"/> object by the <see cref="ChecksumAlgo.Sha256"/> algorithm; otherwise, <see langword="default"/>.</param>
        /// <returns><see langword="true"/> if the specified <paramref name="source"/> could be hashed by the <see cref="ChecksumAlgo.Sha256"/> algorithm; otherwise, <see langword="false"/>.</returns>
        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static bool TryGetCipher<TSource>(this TSource source, out ulong hash) =>
            source.TryGetCipher(ChecksumAlgo.Sha256, out hash);

        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static bool TryGetChecksum<TSource>(this TSource source, ChecksumAlgo algorithm, [NotNullWhen(true)] out string hash)
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
        public static bool TryGetChecksum<TSource>(this TSource source, [NotNullWhen(true)] out string hash) =>
            source.TryGetChecksum(ChecksumAlgo.Sha256, out hash);

        /// <summary>Tries to hash all files of this <paramref name="dirInfo"/> object with the specified <paramref name="algorithm"/> and returns a <see cref="bool"/> value that determines whether the task was successful. All possible exceptions are caught.</summary>
        /// <param name="dirInfo">The directory that contains the files to hash.</param>
        /// <param name="searchOption">One of the enumeration values that specifies whether the operation should include only the current directory or all subdirectories.</param>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <param name="result">If successful, a sequence of <see cref="string"/>-based <see cref="KeyValuePair"/>&lt;<see langword="FilePath"/>, <see langword="Checksum"/>&gt; objects provided by an <see cref="IDictionary{TKey, TValue}"/> object that contains the result of hashing the files of the specified <paramref name="dirInfo"/> by the specified <paramref name="algorithm"/>; otherwise, <see langword="default"/>.</param>
        /// <remarks>Note that the performance of this function has been optimized and should only be limited by the read speed of the hard disk.</remarks>
        /// <returns><see langword="true"/> if the files of the specified <paramref name="dirInfo"/> could be hashed by the specified <paramref name="algorithm"/>; otherwise, <see langword="false"/>.</returns>
        public static bool TryGetChecksums(this DirectoryInfo dirInfo, SearchOption searchOption, ChecksumAlgo algorithm, [NotNullWhen(true)] out IDictionary<string, string> result)
        {
            try
            {
                result = dirInfo.GetChecksums(searchOption, algorithm);
                return result.Any();
            }
            catch
            {
                result = default;
                return false;
            }
        }

        /// <summary>Tries to hash all files of this <paramref name="dirInfo"/> object with the <see cref="ChecksumAlgo.Sha256"/> algorithm and returns a <see cref="bool"/> value that determines whether the task was successful. All possible exceptions are caught.</summary>
        /// <returns><see langword="true"/> if the files of the specified <paramref name="dirInfo"/> could be hashed by the <see cref="ChecksumAlgo.Sha256"/> algorithm; otherwise, <see langword="false"/>.</returns>
        /// <inheritdoc cref="TryGetChecksums(DirectoryInfo, SearchOption, ChecksumAlgo, out IDictionary{string, string})"/>
        public static bool TryGetChecksums(this DirectoryInfo dirInfo, ChecksumAlgo algorithm, [NotNullWhen(true)] out IDictionary<string, string> result) =>
            dirInfo.TryGetChecksums(SearchOption.AllDirectories, algorithm, out result);

        /// <inheritdoc cref="TryGetChecksums(DirectoryInfo, ChecksumAlgo, out IDictionary{string, string})"/>
        public static bool TryGetChecksums(this DirectoryInfo dirInfo, [NotNullWhen(true)] out IDictionary<string, string> result) =>
            dirInfo.TryGetChecksums(SearchOption.AllDirectories, ChecksumAlgo.Sha256, out result);

        /// <summary>Creates a default instance of this algorithm.</summary>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <returns>A default instance of the specified algorithm.</returns>
        public static IChecksumAlgorithm GetDefaultInstance(this ChecksumAlgo algorithm) =>
            algorithm switch
            {
                ChecksumAlgo.Adler32 => Adler32.Create(),
                ChecksumAlgo.Crc8 => Crc.Create(CrcOptions.Crc.Default),
                ChecksumAlgo.Crc8Autosar => Crc.Create(CrcOptions.Crc.Autosar),
                ChecksumAlgo.Crc8Bluetooth => Crc.Create(CrcOptions.Crc.Bluetooth),
                ChecksumAlgo.Crc8Cdma2000 => Crc.Create(CrcOptions.Crc.Cdma2000),
                ChecksumAlgo.Crc8Darc => Crc.Create(CrcOptions.Crc.Darc),
                ChecksumAlgo.Crc8DvbS2 => Crc.Create(CrcOptions.Crc.DvbS2),
                ChecksumAlgo.Crc8GsmA => Crc.Create(CrcOptions.Crc.GsmA),
                ChecksumAlgo.Crc8GsmB => Crc.Create(CrcOptions.Crc.GsmB),
                ChecksumAlgo.Crc8I4321 => Crc.Create(CrcOptions.Crc.I4321),
                ChecksumAlgo.Crc8ICode => Crc.Create(CrcOptions.Crc.ICode),
                ChecksumAlgo.Crc8Lte => Crc.Create(CrcOptions.Crc.Lte),
                ChecksumAlgo.Crc8Maxim => Crc.Create(CrcOptions.Crc.Maxim),
                ChecksumAlgo.Crc8MifareMad => Crc.Create(CrcOptions.Crc.MifareMad),
                ChecksumAlgo.Crc8Nrsc5 => Crc.Create(CrcOptions.Crc.Nrsc5),
                ChecksumAlgo.Crc8OpenSafety => Crc.Create(CrcOptions.Crc.OpenSafety),
                ChecksumAlgo.Crc8Rohc => Crc.Create(CrcOptions.Crc.Rohc),
                ChecksumAlgo.Crc8SaeJ1850 => Crc.Create(CrcOptions.Crc.SaeJ1850),
                ChecksumAlgo.Crc8Tech3250 => Crc.Create(CrcOptions.Crc.Tech3250),
                ChecksumAlgo.Crc8Wcdma => Crc.Create(CrcOptions.Crc.Wcdma),
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
                ChecksumAlgo.Crc32CdRomEdc => Crc.Create(CrcOptions.Crc32.CdRomEdc),
                ChecksumAlgo.Crc32D => Crc.Create(CrcOptions.Crc32.D),
                ChecksumAlgo.Crc32JamCrc => Crc.Create(CrcOptions.Crc32.JamCrc),
                ChecksumAlgo.Crc32Mpeg2 => Crc.Create(CrcOptions.Crc32.Mpeg2),
                ChecksumAlgo.Crc32Posix => Crc.Create(CrcOptions.Crc32.Posix),
                ChecksumAlgo.Crc32Q => Crc.Create(CrcOptions.Crc32.Q),
                ChecksumAlgo.Crc32Xfer => Crc.Create(CrcOptions.Crc32.Xfer),
                ChecksumAlgo.Crc32Xz => Crc.Create(CrcOptions.Crc32.Xz),
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

        internal static IChecksumResult InternalComputeHash<TSource>(this IChecksumAlgorithm instance, TSource source, bool restoreStreamPos)
        {
            if (instance == null)
                throw new ArgumentNullException(nameof(instance));
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            switch (source)
            {
                case BigInteger x:
                    instance.ComputeHash(x.ToByteArray());
                    break;
                case char x:
                    instance.ComputeHash(x.ToString());
                    break;
                case IEnumerable<byte> x:
                    instance.ComputeHash(x as byte[] ?? x.ToArray());
                    break;
                case Memory<byte> x:
                    instance.ComputeHash(x.Span);
                    break;
                case ReadOnlySequence<byte> x:
                    instance.ComputeHash(x.FirstSpan);
                    break;
                case ReadOnlySequenceSegment<byte> x:
                    instance.ComputeHash(x.Memory.Span);
                    break;
                case IEnumerable<char> x:
                    instance.ComputeHash(x as string ?? new string(x.ToArray()));
                    break;
                case Memory<char> x:
                    instance.ComputeHash(new string(x.Span));
                    break;
                case ReadOnlySequence<char> x:
                    instance.ComputeHash(new string(x.FirstSpan));
                    break;
                case ReadOnlySequenceSegment<char> x:
                    instance.ComputeHash(new string(x.Memory.Span));
                    break;
                case StreamReader x:
                    LocalProcessStream(instance, x.BaseStream, restoreStreamPos);
                    break;
                case Stream x:
                    LocalProcessStream(instance, x, restoreStreamPos);
                    break;
                case FileInfo x:
                    instance.ComputeHash(x);
                    break;
                default:
#if DEBUG
                    instance.ComputeHash(LocalGetByteArray(source));
#else
                    try
                    {
                        instance.ComputeHash(LocalGetByteArray(source));
                    }
                    catch (ArgumentException)
                    {
                        // Fallback
                        using var ms = new MemoryStream();
                        using var jw = new Utf8JsonWriter(ms, new JsonWriterOptions { SkipValidation = true });
                        JsonSerializer.Serialize(jw, source);
                        ms.Position = 0L;
                        instance.ComputeHash(ms);
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
                instance.ComputeHash(stream);
                if (restorePos && pos >= 0)
                    stream.Position = pos;
            }
        }
    }
}
