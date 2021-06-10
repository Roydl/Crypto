namespace Roydl.Crypto.Internal
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.Linq;
    using System.Numerics;

    internal static class NumericHelper
    {
        internal static TInteger CreateBitMask<TInteger>(int bitWidth) where TInteger : struct, IComparable, IFormattable
        {
            var size = (int)MathF.Ceiling(bitWidth / 8f);
            switch (0xff.FromTo<int, TInteger>())
            {
                case byte x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= (byte)(0xff << (8 * i));
                    return (TInteger)(object)mask;
                }
                case short x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= (short)(0xff << (8 * i));
                    return (TInteger)(object)mask;
                }
                case ushort x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= (ushort)(0xff << (8 * i));
                    return (TInteger)(object)mask;
                }
                case int x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xff << (8 * i);
                    return (TInteger)(object)mask;
                }
                case uint x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xffu << (8 * i);
                    return (TInteger)(object)mask;
                }
                case long x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xffL << (8 * i);
                    return (TInteger)(object)mask;
                }
                case ulong x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xffuL << (8 * i);
                    return (TInteger)(object)mask;
                }
                case BigInteger x:
                {
                    var mask = x;
                    BigInteger b = 0xff;
                    for (var i = 1; i < size; i++)
                        mask ^= b << (8 * i);
                    return (TInteger)(object)mask;
                }
                default:
                    throw new NotSupportedException();
            }
        }

        internal static TInteger ReverseBits<TInteger>(this TInteger value) where TInteger : struct, IComparable, IFormattable
        {
            // String conversion is slower than shifting bits,
            // but it more accurate for some unusual bit widths.
            var bits = value switch
            {
                sbyte x => Convert.ToString(x, 2),
                byte x => Convert.ToString(x, 2),
                short x => Convert.ToString(x, 2),
                ushort x => Convert.ToString(x, 2),
                int x => Convert.ToString(x, 2),
                uint x => Convert.ToString(x, 2),
                long x => Convert.ToString(x, 2),
                ulong x => Convert.ToString((long)x, 2),
                _ => throw new NotSupportedException()
            };
            var size = bits.Length;
            while (size % 4 != 0)
                size++;
            if (bits.Length < size)
                bits = bits.PadLeft(size, '0');
            bits = new string(bits.Reverse().ToArray());
            return value switch
            {
                sbyte => (TInteger)(object)Convert.ToSByte(bits, 2),
                byte => (TInteger)(object)Convert.ToByte(bits, 2),
                short => (TInteger)(object)Convert.ToInt16(bits, 2),
                ushort => (TInteger)(object)Convert.ToUInt16(bits, 2),
                int => (TInteger)(object)Convert.ToInt32(bits, 2),
                uint => (TInteger)(object)Convert.ToUInt32(bits, 2),
                long => (TInteger)(object)Convert.ToInt64(bits, 2),
                _ => (TInteger)(object)Convert.ToUInt64(bits, 2)
            };
        }

        internal static TIntegerOut FromTo<TIntegerIn, TIntegerOut>(this TIntegerIn value) where TIntegerIn : struct, IComparable, IFormattable where TIntegerOut : struct, IComparable, IFormattable
        {
            if (typeof(TIntegerIn) == typeof(TIntegerOut))
                return (TIntegerOut)(object)value;

            // unchecked assignment
            return default(TIntegerOut) switch
            {
                sbyte => value switch
                {
                    byte x => (TIntegerOut)(object)(sbyte)x,
                    short x => (TIntegerOut)(object)(sbyte)x,
                    ushort x => (TIntegerOut)(object)(sbyte)x,
                    int x => (TIntegerOut)(object)(sbyte)x,
                    uint x => (TIntegerOut)(object)(sbyte)x,
                    long x => (TIntegerOut)(object)(sbyte)x,
                    ulong x => (TIntegerOut)(object)(sbyte)x,
                    BigInteger x => (TIntegerOut)(object)(sbyte)(x & sbyte.MaxValue),
                    _ => throw new NotSupportedException()
                },
                byte => value switch
                {
                    sbyte x => (TIntegerOut)(object)(byte)x,
                    short x => (TIntegerOut)(object)(byte)x,
                    ushort x => (TIntegerOut)(object)(byte)x,
                    int x => (TIntegerOut)(object)(byte)x,
                    uint x => (TIntegerOut)(object)(byte)x,
                    long x => (TIntegerOut)(object)(byte)x,
                    ulong x => (TIntegerOut)(object)(byte)x,
                    BigInteger x => (TIntegerOut)(object)(byte)(x & byte.MaxValue),
                    _ => throw new NotSupportedException()
                },
                short => value switch
                {
                    sbyte x => (TIntegerOut)(object)(short)x,
                    byte x => (TIntegerOut)(object)(short)x,
                    ushort x => (TIntegerOut)(object)(short)x,
                    int x => (TIntegerOut)(object)(short)x,
                    uint x => (TIntegerOut)(object)(short)x,
                    long x => (TIntegerOut)(object)(short)x,
                    ulong x => (TIntegerOut)(object)(short)x,
                    BigInteger x => (TIntegerOut)(object)(short)(x & short.MaxValue),
                    _ => throw new NotSupportedException()
                },
                ushort => value switch
                {
                    sbyte x => (TIntegerOut)(object)(ushort)x,
                    byte x => (TIntegerOut)(object)(ushort)x,
                    short x => (TIntegerOut)(object)(ushort)x,
                    int x => (TIntegerOut)(object)(ushort)x,
                    uint x => (TIntegerOut)(object)(ushort)x,
                    long x => (TIntegerOut)(object)(ushort)x,
                    ulong x => (TIntegerOut)(object)(ushort)x,
                    BigInteger x => (TIntegerOut)(object)(ushort)(x & ushort.MaxValue),
                    _ => throw new NotSupportedException()
                },
                int => value switch
                {
                    sbyte x => (TIntegerOut)(object)(int)x,
                    byte x => (TIntegerOut)(object)(int)x,
                    short x => (TIntegerOut)(object)(int)x,
                    ushort x => (TIntegerOut)(object)(int)x,
                    uint x => (TIntegerOut)(object)(int)x,
                    long x => (TIntegerOut)(object)(int)x,
                    ulong x => (TIntegerOut)(object)(int)x,
                    BigInteger x => (TIntegerOut)(object)(int)(x & int.MaxValue),
                    _ => throw new NotSupportedException()
                },
                uint => value switch
                {
                    sbyte x => (TIntegerOut)(object)(uint)x,
                    byte x => (TIntegerOut)(object)(uint)x,
                    short x => (TIntegerOut)(object)(uint)x,
                    ushort x => (TIntegerOut)(object)(uint)x,
                    int x => (TIntegerOut)(object)(uint)x,
                    long x => (TIntegerOut)(object)(uint)x,
                    ulong x => (TIntegerOut)(object)(uint)x,
                    BigInteger x => (TIntegerOut)(object)(uint)(x & uint.MaxValue),
                    _ => throw new NotSupportedException()
                },
                long => value switch
                {
                    sbyte x => (TIntegerOut)(object)(long)x,
                    byte x => (TIntegerOut)(object)(long)x,
                    short x => (TIntegerOut)(object)(long)x,
                    ushort x => (TIntegerOut)(object)(long)x,
                    int x => (TIntegerOut)(object)(long)x,
                    uint x => (TIntegerOut)(object)(long)x,
                    ulong x => (TIntegerOut)(object)(long)x,
                    BigInteger x => (TIntegerOut)(object)(long)(x & long.MaxValue),
                    _ => throw new NotSupportedException()
                },
                ulong => value switch
                {
                    sbyte x => (TIntegerOut)(object)(ulong)x,
                    byte x => (TIntegerOut)(object)(ulong)x,
                    short x => (TIntegerOut)(object)(ulong)x,
                    ushort x => (TIntegerOut)(object)(ulong)x,
                    int x => (TIntegerOut)(object)(ulong)x,
                    uint x => (TIntegerOut)(object)(ulong)x,
                    long x => (TIntegerOut)(object)(ulong)x,
                    BigInteger x => (TIntegerOut)(object)(ulong)(x & ulong.MaxValue),
                    _ => throw new NotSupportedException()
                },
                BigInteger => value switch
                {
                    sbyte x => (TIntegerOut)(object)(BigInteger)x,
                    byte x => (TIntegerOut)(object)(BigInteger)x,
                    short x => (TIntegerOut)(object)(BigInteger)x,
                    ushort x => (TIntegerOut)(object)(BigInteger)x,
                    int x => (TIntegerOut)(object)(BigInteger)x,
                    uint x => (TIntegerOut)(object)(BigInteger)x,
                    long x => (TIntegerOut)(object)(BigInteger)x,
                    ulong x => (TIntegerOut)(object)(BigInteger)x,
                    _ => throw new NotSupportedException()
                },
                _ => throw new NotSupportedException()
            };
        }

        internal static string ToHexStr<TInteger>(this TInteger num, int padding, bool prefix) where TInteger : struct, IComparable, IFormattable
        {
            var str = num.ToString("x2", null);
            if (padding > 2)
                str = str.PadLeft(padding, '0');
            if (prefix)
                str = $"0x{str}";
            return str;
        }

        internal static BigInteger ToBigInt([AllowNull] this string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return BigInteger.Zero;
            var flags = value.StartsWith("0x") ? NumberStyles.HexNumber : NumberStyles.Any;
            if (flags == NumberStyles.HexNumber)
                value = value[2..];
            return BigInteger.TryParse(value, flags, null, out var result) ? result : BigInteger.Zero;
        }
    }
}
