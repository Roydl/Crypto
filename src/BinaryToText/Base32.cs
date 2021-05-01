namespace Roydl.Crypto.BinaryToText
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using AbstractSamples;
    using Properties;

    /// <summary>
    ///     Initializes a new instance of the <see cref="Base32"/> class.
    /// </summary>
    public sealed class Base32 : BinaryToTextSample
    {
        private static readonly byte[] CharacterTable32 =
        {
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
            0x59, 0x5a, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
        };

        /// <summary>
        ///     Encodes the specified input stream into the specified output stream.
        /// </summary>
        /// <param name="inputStream">
        ///     The input stream to encode.
        /// </param>
        /// <param name="outputStream">
        ///     The output stream for encoding.
        /// </param>
        /// <param name="lineLength">
        ///     The length of lines.
        /// </param>
        /// <param name="dispose">
        ///     <see langword="true"/> to release all resources used by the input and
        ///     output <see cref="Stream"/>; otherwise, <see langword="false"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     inputStream or outputStream is null.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     inputStream is larger than 128 MB.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     inputStream or outputStream is invalid.
        /// </exception>
        /// <exception cref="NotSupportedException">
        ///     inputStream is not readable -or- outputStream is not writable.
        /// </exception>
        /// <exception cref="IOException">
        ///     An I/O error occurred, such as the specified file cannot be found.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///     Methods were called after the inputStream or outputStream was closed.
        /// </exception>
        public override void EncodeStream(Stream inputStream, Stream outputStream, int lineLength = 0, bool dispose = false)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));
            if (inputStream.Length > 0x8000000)
                throw new ArgumentOutOfRangeException(nameof(inputStream));
            try
            {
                int i;
                var ba = new byte[inputStream.Length];
                var p = 0;
                while ((i = inputStream.Read(ba, 0, ba.Length)) > 0)
                {
                    var len = (i > ba.Length ? Math.Pow(ba.Length, Math.Max(Math.Floor((double)i / ba.Length), 1)) : i) * 8;
                    for (var j = 0; j < len; j += 5)
                    {
                        var c = ba[j / 8] << 8;
                        if (j / 8 + 1 < ba.Length)
                            c |= ba[j / 8 + 1];
                        c = 31 & (c >> (16 - j % 8 - 5));
                        WriteLine(outputStream, CharacterTable32[c], lineLength, ref p);
                    }
                }
            }
            finally
            {
                if (dispose)
                {
                    inputStream.Dispose();
                    outputStream.Dispose();
                }
            }
        }

        /// <summary>
        ///     Decodes the specified input stream into the specified output stream.
        /// </summary>
        /// <param name="inputStream">
        ///     The input stream to decode.
        /// </param>
        /// <param name="outputStream">
        ///     The output stream for decoding.
        /// </param>
        /// <param name="dispose">
        ///     <see langword="true"/> to release all resources used by the input and
        ///     output <see cref="Stream"/>; otherwise, <see langword="false"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     inputStream or outputStream is null.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     inputStream is larger than 128 MB.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     inputStream or outputStream is invalid.
        /// </exception>
        /// <exception cref="DecoderFallbackException">
        ///     inputStream contains invalid characters.
        /// </exception>
        /// <exception cref="NotSupportedException">
        ///     inputStream is not readable -or- outputStream is not writable.
        /// </exception>
        /// <exception cref="IOException">
        ///     An I/O error occurred, such as the specified file cannot be found.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///     Methods were called after the inputStream or outputStream was closed.
        /// </exception>
        public override void DecodeStream(Stream inputStream, Stream outputStream, bool dispose = false)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));
            if (inputStream.Length > 0x8000000)
                throw new ArgumentOutOfRangeException(nameof(inputStream));
            try
            {
                var ba1 = new byte[inputStream.Length];
                var a32 = Utils.Utf8NoBom.GetString(CharacterTable32);
                while (inputStream.Read(ba1, 0, ba1.Length) > 0)
                {
                    var ba2 = ba1.Where(b => b > 0 && !Separator.Contains(b)).ToArray();
                    if (ba2.Any(x => !CharacterTable32.Contains(x)))
                        throw new DecoderFallbackException(ExceptionMessages.CharsInStreamAreInvalid);
                    var len = ba2.Length * 5;
                    for (var i = 0; i < len; i += 8)
                    {
                        var b = ba2[i / 5];
                        var c = a32.IndexOf((char)b) << 10;
                        if (i / 5 + 1 < ba2.Length)
                        {
                            b = ba2[i / 5 + 1];
                            c |= a32.IndexOf((char)b) << 5;
                        }
                        if (i / 5 + 2 < ba2.Length)
                        {
                            b = ba2[i / 5 + 2];
                            c |= a32.IndexOf((char)b);
                        }
                        c = 255 & (c >> (15 - i % 5 - 8));
                        if (i + 5 > len && c <= 0)
                            break;
                        outputStream.WriteByte((byte)c);
                    }
                }
            }
            finally
            {
                if (dispose)
                {
                    inputStream.Dispose();
                    outputStream.Dispose();
                }
            }
        }
    }
}
