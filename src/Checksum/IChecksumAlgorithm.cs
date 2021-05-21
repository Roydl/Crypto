namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>
    ///     Represents the interface for checksum encryption algorithms.
    /// </summary>
    public interface IChecksumAlgorithm
    {
        /// <summary>
        ///     Gets the hash size in bits.
        /// </summary>
        int HashBits { get; }

        /// <summary>
        ///     Gets the string hash size.
        /// </summary>
        /// <remarks>
        ///     For more information, see
        ///     <see cref="Hash">
        ///         here
        ///     </see>
        ///     .
        /// </remarks>
        int HashSize { get; }

        /// <summary>
        ///     Gets the raw hash size.
        /// </summary>
        /// <remarks>
        ///     For more information, see
        ///     <see cref="RawHash">
        ///         here
        ///     </see>
        ///     .
        /// </remarks>
        int RawHashSize { get; }

        /// <summary>
        ///     Gets the string representation of the computed hash code.
        /// </summary>
        /// <remarks>
        ///     For more information, see
        ///     <see cref="HashSize">
        ///         here
        ///     </see>
        ///     .
        /// </remarks>
        string Hash { get; }

        /// <summary>
        ///     Gets the sequence of bytes of the computed hash code.
        /// </summary>
        /// <remarks>
        ///     For more information, see
        ///     <see cref="RawHashSize">
        ///         here
        ///     </see>
        ///     .
        /// </remarks>
        ReadOnlyMemory<byte> RawHash { get; }

        /// <summary>
        ///     Gets the 64-bit unsigned integer representation of the computed hash code.
        /// </summary>
        /// <remarks>
        ///     For algorithms with up to 64 bits, this field holds the real raw hash.
        /// </remarks>
        ulong HashNumber { get; }

        /// <summary>
        ///     Encrypts the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     bytes is null.
        /// </exception>
        void Encrypt(Stream stream);

        /// <summary>
        ///     Encrypts the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     bytes is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     bytes is empty.
        /// </exception>
        void Encrypt(byte[] bytes);

        /// <summary>
        ///     Encrypts the specified string.
        /// </summary>
        /// <param name="text">
        ///     The string to encrypt.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     text is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     text is empty.
        /// </exception>
        void Encrypt(string text);

        /// <summary>
        ///     Encrypts the specified file.
        /// </summary>
        /// <param name="path">
        ///     The full path of the file to encrypt.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     path is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     path is empty.
        /// </exception>
        /// <exception cref="FileNotFoundException">
        ///     path cannot be found.
        /// </exception>
        void EncryptFile(string path);

        /// <summary>
        ///     Converts the <see cref="RawHash"/> of this instance to its equivalent
        ///     string representation.
        /// </summary>
        /// <param name="uppercase">
        ///     <see langword="true"/> to convert letters to uppercase; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        string ToString(bool uppercase);

        /// <summary>
        ///     Converts the <see cref="RawHash"/> of this instance to its equivalent
        ///     string representation.
        /// </summary>
        string ToString();
    }
}
