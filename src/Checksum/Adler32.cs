namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using Internal;
    using Resources;

    /// <summary>Provides functionality to compute Adler-32 hashes.</summary>
    public sealed class Adler32 : ChecksumAlgorithm<Adler32, uint>
    {
        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        public Adler32() : base(32) => AlgorithmName = nameof(Adler32);

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        /// <returns>A newly created <see cref="Adler32"/> instance.</returns>
        public static Adler32 Create() => new();

        /// <inheritdoc/>
        public override void ComputeHash(Stream stream)
        {
            Reset();
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead)
                throw new NotSupportedException(ExceptionMessages.NotSupportedStreamRead);
            Span<uint> sum = stackalloc[] { 1u, 0u };
            Span<byte> bytes = stackalloc byte[stream.GetBufferSize()];
            int len;
            while ((len = stream.Read(bytes)) > 0)
            {
                for (var i = 0; i < len; i++)
                    AppendData(bytes[i], ref sum);
            }
            FinalizeHash(sum);
        }

        /// <inheritdoc/>
        public override void ComputeHash(ReadOnlySpan<byte> bytes)
        {
            Reset();
            if (bytes.IsEmpty)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            Span<uint> sum = stackalloc[] { 1u, 0u };
            foreach (var value in bytes)
                AppendData(value, ref sum);
            FinalizeHash(sum);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AppendData(byte value, ref Span<uint> hash)
        {
            if (hash.Length < 2)
                throw new IndexOutOfRangeException();
            hash[0] = (hash[0] + value) % 0xfff1;
            hash[1] = (hash[1] + hash[0]) % 0xfff1;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void FinalizeHash(ReadOnlySpan<uint> hash)
        {
            if (hash.Length < 2)
                throw new IndexOutOfRangeException();
            var sum = ((hash[1] << 16) | hash[0]) & uint.MaxValue;
            HashNumber = sum;
            RawHash = CryptoUtils.GetByteArray(sum, !BitConverter.IsLittleEndian);
        }
    }
}
