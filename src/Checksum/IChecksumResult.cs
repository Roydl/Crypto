﻿namespace Roydl.Crypto.Checksum
{
    using System;

    /// <summary>Represents the interface for checksum results.</summary>
    public interface IChecksumResult
    {
        /// <summary>Gets the string hash size.</summary>
        /// <remarks>For more information, see <see cref="Hash">Hash</see>.</remarks>
        int HashSize { get; }

        /// <summary>Gets the raw hash size.</summary>
        /// <remarks>For more information, see <see cref="RawHash">RawHash</see>.</remarks>
        int RawHashSize { get; }

        /// <summary>Gets the string representation of the last computed hash code.</summary>
        /// <remarks>For more information, see <see cref="HashSize">HashSize</see>.</remarks>
        string Hash { get; }

        /// <summary>Gets the sequence of bytes of the last computed hash code.</summary>
        /// <remarks>For more information, see <see cref="RawHashSize">RawHashSize</see>.</remarks>
        ReadOnlyMemory<byte> RawHash { get; }

        /// <summary>Removes the saved data from this instance.</summary>
        void Reset();
    }

    /// <summary>Represents the interface for checksum results.</summary>
    /// <typeparam name="TCipher">The integral type of <see cref="HashNumber"/>.</typeparam>
    public interface IChecksumResult<out TCipher> : IChecksumResult where TCipher : struct, IComparable, IFormattable
    {
        /// <summary>Gets the integral numeric representation of the last computed hash code.</summary>
        /// <remarks>For some algorithms, this field holds the real raw hash.</remarks>
        TCipher HashNumber { get; }
    }
}