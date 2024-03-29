﻿namespace Roydl.Crypto.Checksum
{
    using Internal;
    using Resources;
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;

    /// <summary>Provides functionality to compute Adler-32 hashes.</summary>
    public sealed class Adler32 : ChecksumAlgorithm<Adler32, uint>
    {
        private const int ChunkSize = 16;
        private const uint ModAdler = 0xfff1u;

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        public Adler32() : base(32) => AlgorithmName = nameof(Adler32);

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        /// <returns>A newly created <see cref="Adler32"/> instance.</returns>
        public static Adler32 Create() => new();

        /// <inheritdoc/>
        public override unsafe void ComputeHash(Stream stream)
        {
            Reset();
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead)
                throw new NotSupportedException(ExceptionMessages.NotSupportedStreamRead);
            var sum1 = 1u;
            var sum2 = 0u;
            Span<byte> bytes = stackalloc byte[stream.GetBufferSize()];
            fixed (byte* input = bytes)
            {
                int len;
                while ((len = stream.Read(bytes)) > 0)
                    AppendData(input, len, ref sum1, ref sum2);
            }
            FinalizeHash(sum1, sum2);
        }

        /// <inheritdoc/>
        public override unsafe void ComputeHash(ReadOnlySpan<byte> bytes)
        {
            Reset();
            if (bytes.IsEmpty)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            var sum1 = 1u;
            var sum2 = 0u;
            fixed (byte* input = bytes)
                AppendData(input, bytes.Length, ref sum1, ref sum2);
            FinalizeHash(sum1, sum2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void AppendData(byte* input, int len, ref uint hash1, ref uint hash2)
        {
            var sum1 = hash1;
            var sum2 = hash2;
            var i = 0;
            for (; len >= ChunkSize; i += ChunkSize, len -= ChunkSize)
            {
                for (var j = 0; j < ChunkSize; j++)
                {
                    sum1 += Unsafe.Read<byte>(input + i + j);
                    sum2 += sum1;
                }
                if (i % 5552 != 0)
                    continue;
                sum1 %= ModAdler;
                sum2 %= ModAdler;
            }
            sum1 %= ModAdler;
            sum2 %= ModAdler;
            while (--len >= 0)
            {
                sum1 = (sum1 + input[i++]) % ModAdler;
                sum2 = (sum1 + sum2) % ModAdler;
            }
            hash1 = sum1;
            hash2 = sum2;
        }

        private void FinalizeHash(uint hash1, uint hash2) =>
            Update(((hash2 << 16) | hash1) & uint.MaxValue);
    }
}
