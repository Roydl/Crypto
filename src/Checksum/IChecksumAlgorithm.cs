﻿namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>Represents the interface for checksum encryption algorithms.</summary>
    public interface IChecksumAlgorithm
    {
        /// <summary>Gets the hash size in bits.</summary>
        int HashBits { get; }

        /// <summary>Gets the string hash size.</summary>
        /// <remarks>For more information, see <see cref="Hash">Hash</see>.</remarks>
        int HashSize { get; }

        /// <summary>Gets the raw hash size.</summary>
        /// <remarks>For more information, see <see cref="RawHash">RawHash</see>.</remarks>
        int RawHashSize { get; }

        /// <summary>Gets the string representation of the last computed hash code.</summary>
        /// <remarks>For more information, see <see cref="HashSize">HashSize</see>.</remarks>
        string Hash { get; }

        /// <summary>Gets the 64-bit unsigned integer representation of the last computed hash code.</summary>
        /// <remarks>For algorithms with up to 64 bits, this field holds the real raw hash.</remarks>
        ulong HashNumber { get; }

        /// <summary>Gets the sequence of bytes of the last computed hash code.</summary>
        /// <remarks>For more information, see <see cref="RawHashSize">RawHashSize</see>.</remarks>
        ReadOnlyMemory<byte> RawHash { get; }

        /// <summary>Encrypts the bytes of the specified stream starting at its current position.</summary>
        /// <param name="stream">The stream to encrypt.</param>
        /// <exception cref="ArgumentNullException">stream is null.</exception>
        /// <exception cref="IOException">An I/O error occurs.</exception>
        /// <exception cref="NotSupportedException">stream does not support reading.</exception>
        /// <remarks>For more information, see <see cref="Hash">Hash</see>, <see cref="HashNumber">HashNumber</see> and <see cref="RawHash">RawHash</see>.</remarks>
        void Encrypt(Stream stream);

        /// <summary>Encrypts the specified sequence of bytes.</summary>
        /// <param name="bytes">The sequence of bytes to encrypt.</param>
        /// <exception cref="ArgumentNullException">bytes is null.</exception>
        /// <exception cref="ArgumentException">bytes is empty.</exception>
        /// <remarks>For more information, see <see cref="Hash">Hash</see>, <see cref="HashNumber">HashNumber</see> and <see cref="RawHash">RawHash</see>.</remarks>
        void Encrypt(byte[] bytes);

        /// <summary>Encrypts the specified string.</summary>
        /// <param name="text">The string to encrypt.</param>
        /// <exception cref="ArgumentNullException">text is null.</exception>
        /// <exception cref="ArgumentException">text is empty.</exception>
        /// <inheritdoc cref="Encrypt(byte[])"/>
        void Encrypt(string text);

        /// <summary>Encrypts the specified file.</summary>
        /// <param name="fileInfo">The file to encrypt.</param>
        /// <exception cref="ArgumentNullException">fileInfo is null.</exception>
        /// <exception cref="FileNotFoundException">File cannot be found.</exception>
        /// <remarks>For more information, see <see cref="Hash">Hash</see>, <see cref="HashNumber">HashNumber</see> and <see cref="RawHash">RawHash</see>.</remarks>
        void Encrypt(FileInfo fileInfo);

        /// <summary>Encrypts the specified file.</summary>
        /// <param name="path">The full path of the file to encrypt.</param>
        /// <exception cref="ArgumentNullException">path is null.</exception>
        /// <exception cref="ArgumentException">path is empty.</exception>
        /// <exception cref="FileNotFoundException">path cannot be found.</exception>
        /// <inheritdoc cref="Encrypt(FileInfo)"/>
        void EncryptFile(string path);

        /// <summary>Removes the saved data from this instance.</summary>
        void Reset();

        /// <summary>Converts the <see cref="RawHash">RawHash</see> of this instance to its equivalent string representation.</summary>
        /// <param name="uppercase"><see langword="true"/> to convert letters to uppercase; otherwise, <see langword="false"/>.</param>
        string ToString(bool uppercase);

        /// <inheritdoc cref="ToString(bool)"/>
        string ToString();
    }
}
