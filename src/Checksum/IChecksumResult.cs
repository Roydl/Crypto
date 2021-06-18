namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Diagnostics.CodeAnalysis;

    /// <summary>Represents the interface for checksum results.</summary>
    public interface IChecksumResult
    {
        /// <summary>Gets the string length of a computed hash.</summary>
        /// <remarks>For more information, see <see cref="Hash">Hash</see>.</remarks>
        int HashSize { get; }

        /// <summary>Gets the logical byte sequence length of a computed hash.</summary>
        /// <remarks>For more information, see <see cref="RawHash">RawHash</see>.</remarks>
        int RawHashSize { get; }

        /// <summary>Gets the string representation of the last computed hash.</summary>
        /// <remarks>For more information, see <see cref="HashSize">HashSize</see>.</remarks>
        string Hash
        {
            [return: NotNull]
            get;
        }

        /// <summary>Gets the sequence of bytes of the last computed hash.</summary>
        /// <remarks>For more information, see <see cref="RawHashSize">RawHashSize</see>.</remarks>
        ReadOnlySpan<byte> RawHash { get; }

        /// <summary>Removes the saved hashes from this instance.</summary>
        void Reset();

        /// <summary>Converts the <see cref="IChecksumResult.RawHash">RawHash</see> of this instance to its equivalent string representation.</summary>
        /// <param name="uppercase"><see langword="true"/> to convert letters to uppercase; otherwise, <see langword="false"/>.</param>
        /// <returns>The string representation of the last computed hash.</returns>
        [return: NotNull]
        string ToString(bool uppercase);

        /// <inheritdoc cref="ToString(bool)"/>
        [return: NotNull]
        string ToString();
    }

    /// <summary>Represents the interface for checksum results.</summary>
    /// <typeparam name="TCipher">The integral type of <see cref="CipherHash"/>.</typeparam>
    public interface IChecksumResult<out TCipher> : IChecksumResult where TCipher : struct, IComparable, IFormattable
    {
        /// <summary>Gets the integral numeric representation of the last computed hash.</summary>
        /// <remarks>For some algorithms, this field holds the real raw hash.</remarks>
        TCipher CipherHash { get; }
    }
}
